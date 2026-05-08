# Oversized HTTP Response Line Aborts Client

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/rpki-client/http.c:1498`

## Summary

A malicious HTTPS RPKI repository can send a response status or header line that fills the 32768-byte HTTP read buffer without a newline. `http_read()` then retries reading more data even though the buffer is full and hits an assertion, aborting the HTTP child process instead of failing the request gracefully.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `rpki-client` fetches from an attacker-controlled HTTPS repository.
- The attacker-controlled server sends HTTP response status or header data without `\n`.
- The newline-free line fills the 32768-byte client read buffer.

## Proof

`http_read()` reads TLS data into `conn->buf` and, while parsing `STATE_RESPONSE_STATUS` or `STATE_RESPONSE_HEADER`, calls `http_get_line()`.

If no newline is present, `http_get_line()` returns `NULL`, and `http_read()` jumps to `read_more`.

At `read_more`, the original code asserts:

```c
assert(conn->bufpos < conn->bufsz);
```

A server that sends exactly 32768 bytes of response status/header data without `\n` makes:

```c
conn->bufpos == conn->bufsz
```

The next parser retry reaches `read_more` and deterministically triggers the assertion before `tls_read()` can be called.

The reproduced impact is process-level DoS: the HTTP helper is a separate HTTPS fetch process, and abnormal helper termination is treated by the parent as a run failure.

## Why This Is A Real Bug

This is reachable from network input controlled by an HTTPS repository server. The failure condition does not require memory corruption, timing, or undefined parsing behavior; it follows directly from the parser state machine:

- `http_get_line()` requires `\n`.
- Missing `\n` causes another read attempt.
- The fixed-size read buffer can become full.
- The original code uses an assertion for a runtime input condition.
- Assertion failure aborts the client process instead of returning `HTTP_FAILED`.

Assertions must not be used to enforce externally controlled protocol limits.

## Fix Requirement

Replace the assertion with explicit full-buffer handling. When the buffer is full and no complete response line is available, the client must treat the response line as too long, fail the current request, and continue through normal error handling rather than aborting.

## Patch Rationale

The patch converts the crash condition into a protocol error:

```c
if (conn->bufpos == conn->bufsz) {
	warnx("%s: HTTP response line too long", conn_info(conn));
	return http_failed(conn);
}
```

This preserves the existing fixed buffer limit, reports a clear diagnostic, and uses the existing `http_failed()` path to fail the request cleanly.

The check is placed immediately before `tls_read()`, where the original assertion existed, so all parser states that request more line data receive the same safe behavior when the read buffer is exhausted.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/rpki-client/http.c b/usr.sbin/rpki-client/http.c
index 4f0e778..9ed240a 100644
--- a/usr.sbin/rpki-client/http.c
+++ b/usr.sbin/rpki-client/http.c
@@ -1546,7 +1546,10 @@ http_read(struct http_connection *conn)
 		goto again;
 
 read_more:
-	assert(conn->bufpos < conn->bufsz);
+	if (conn->bufpos == conn->bufsz) {
+		warnx("%s: HTTP response line too long", conn_info(conn));
+		return http_failed(conn);
+	}
 	s = tls_read(conn->tls, conn->buf + conn->bufpos,
 	    conn->bufsz - conn->bufpos);
 	if (s == -1) {
```