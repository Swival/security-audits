# Oversized Proxy Response Line Aborts Client

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`usr.sbin/rpki-client/http.c:1767`

## Summary

An attacker-controlled HTTP proxy can abort `rpki-client` by sending a proxy status line or proxy header line longer than `HTTP_BUF_SIZE` without a newline. The proxy read path fills the 32768-byte buffer, returns `WANT_POLLIN` because no complete line is available, then re-enters `proxy_read()` and hits `assert(conn->bufpos < conn->bufsz)` before the proxy request can fail cleanly.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client uses an attacker-controlled `http_proxy`.
- Assertions are enabled.

## Proof

- `http_proxy` is read during setup, and requests are routed through the configured proxy.
- `proxy_write()` transitions the connection to `STATE_PROXY_STATUS`, allocates a `HTTP_BUF_SIZE` read buffer, and waits for proxy input.
- `proxy_read()` asserts `conn->bufpos < conn->bufsz` before each read.
- `http_get_line()` only returns a line when `\n` exists in the retained buffer.
- If the proxy sends 32769 non-newline bytes as the status line, or a valid status followed by a 32769-byte non-newline header, `conn->bufpos` reaches 32768.
- With no newline present, `http_get_line()` returns `NULL`, `proxy_read()` returns `WANT_POLLIN`, and the full buffer remains retained.
- On the next readable event, `proxy_read()` immediately executes the pre-read assertion with `conn->bufpos == conn->bufsz`, causing a deterministic abort.
- The abort propagates as an abnormal HTTP child termination and causes the client run to fail.

## Why This Is A Real Bug

The proxy response parser treats “no complete line yet” as a recoverable polling condition even when the fixed-size line buffer is already full. Because no bytes are consumed without a newline, further progress is impossible. The next read attempt violates the function’s own buffer-space invariant and aborts the process instead of reporting a normal proxy request failure.

## Fix Requirement

Detect a full proxy response line buffer with no newline and return `http_failed(conn)` rather than `WANT_POLLIN`.

## Patch Rationale

The patch adds explicit full-buffer checks in both proxy line parsing states:

- `STATE_PROXY_STATUS`: fails the connection if the proxy status line fills the buffer without a newline.
- `STATE_PROXY_RESPONSE`: fails the connection if any proxy header line fills the buffer without a newline.

This preserves the existing behavior for incomplete lines that still have available buffer space, while converting the impossible-to-progress oversized-line condition into a controlled request failure.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpki-client/http.c b/usr.sbin/rpki-client/http.c
index 4f0e778..659fad8 100644
--- a/usr.sbin/rpki-client/http.c
+++ b/usr.sbin/rpki-client/http.c
@@ -1793,8 +1793,11 @@ again:
 	switch (conn->state) {
 	case STATE_PROXY_STATUS:
 		buf = http_get_line(conn);
-		if (buf == NULL)
+		if (buf == NULL) {
+			if (conn->bufpos == conn->bufsz)
+				return http_failed(conn);
 			return WANT_POLLIN;
+		}
 		if (http_parse_status(conn, buf) == -1) {
 			free(buf);
 			return http_failed(conn);
@@ -1806,8 +1809,11 @@ again:
 		done = 0;
 		while (!done) {
 			buf = http_get_line(conn);
-			if (buf == NULL)
+			if (buf == NULL) {
+				if (conn->bufpos == conn->bufsz)
+					return http_failed(conn);
 				return WANT_POLLIN;
+			}
 			/* empty line, end of header */
 			if (*buf == '\0')
 				done = 1;
```