# Unbounded Response Headers Exhaust Memory

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/acme-client/http.c:598`

## Summary

`http_head_read()` reads HTTPS response headers into `trans->hbuf` until it finds `\r\n\r\n`, reaches EOF/short read, or hits an error. Before the patch, there was no maximum header size. An attacker-controlled ACME HTTPS endpoint could continuously send full `BUFSIZ` chunks without the header terminator, forcing unbounded reallocations and memory exhaustion during certificate renewal.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client connects to an attacker-controlled ACME HTTPS endpoint.
- The endpoint can send an HTTP response header stream that omits `\r\n\r\n`.
- The endpoint keeps the TLS stream alive and sends full `BUFSIZ` reads.

## Proof

The finding was reproduced from source inspection.

- `netproc.c` reaches `http_get()` for ACME GET, HEAD, and POST requests.
- `http_get()` calls `http_head_read()` before processing the response body at `usr.sbin/acme-client/http.c:674`.
- `http_head_read()` repeatedly calls `http_read(buf, sizeof(buf), http)`.
- If the peer keeps sending data, `http_read()` can fill the local `BUFSIZ` buffer on each iteration.
- Each received chunk is appended with `recallocarray(trans->hbuf, trans->hbufsz, trans->hbufsz + ssz, 1)` at `usr.sbin/acme-client/http.c:598`.
- The loop exits only when `memmem()` finds `\r\n\r\n`, when `ssz != sizeof(buf)`, or when a read/allocation error occurs.
- A malicious server that never sends `\r\n\r\n` and keeps returning full blocks causes `trans->hbufsz` to grow until allocation failure or system memory pressure.

## Why This Is A Real Bug

The response header bytes are attacker-controlled once the client connects to the selected HTTPS endpoint. The vulnerable loop stores all received header bytes before parsing, but did not enforce a protocol or implementation limit on header size. Because the exit condition depends on an attacker-supplied terminator or a short read, a malicious peer can keep the loop allocating memory indefinitely. The resulting allocation failure or OOM pressure can abort the ACME request and prevent certificate renewal.

## Fix Requirement

Enforce a maximum HTTP response header size in `http_head_read()` and abort the transfer before growing `trans->hbuf` beyond that limit.

## Patch Rationale

The patch defines `HTTP_HEAD_MAX` as `64 * 1024` and checks the pending append before calling `recallocarray()`. The guard rejects responses whose accumulated header buffer would exceed the limit, logs `header too large`, and returns `NULL`. This preserves existing parsing behavior for normal responses while preventing attacker-controlled unbounded growth.

The subtraction-based check also avoids unsigned overflow:

```c
if (trans->hbufsz > HTTP_HEAD_MAX ||
    (size_t)ssz > HTTP_HEAD_MAX - trans->hbufsz) {
	warnx("%s: header too large", http->src.ip);
	return NULL;
}
```

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/acme-client/http.c b/usr.sbin/acme-client/http.c
index 1d745ce..c93c6c0 100644
--- a/usr.sbin/acme-client/http.c
+++ b/usr.sbin/acme-client/http.c
@@ -62,6 +62,8 @@ struct	http {
 	struct tls	  *ctx;    /* TLS context */
 };
 
+#define	HTTP_HEAD_MAX	(64 * 1024)
+
 struct tls_config *tlscfg;
 
 static ssize_t
@@ -595,6 +597,11 @@ http_head_read(const struct http *http, struct httpxfer *trans, size_t *sz)
 			return NULL;
 		else if (ssz == 0)
 			break;
+		if (trans->hbufsz > HTTP_HEAD_MAX ||
+		    (size_t)ssz > HTTP_HEAD_MAX - trans->hbufsz) {
+			warnx("%s: header too large", http->src.ip);
+			return NULL;
+		}
 		pp = recallocarray(trans->hbuf,
 		    trans->hbufsz, trans->hbufsz + ssz, 1);
 		if (pp == NULL) {
```