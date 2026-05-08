# Unbounded HTTP Header Buffering

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/ocspcheck/http.c:648`

## Summary

`ocspcheck` reads HTTP response headers from an OCSP responder into a dynamically growing heap buffer without enforcing a maximum header size. An attacker-controlled OCSP responder can keep the connection open and stream full `BUFSIZ` blocks that never contain `\r\n\r\n`, causing repeated `realloc()` growth until memory allocation fails or the process/system is exhausted.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ocspcheck` connects to an attacker-controlled OCSP responder.
- The responder sends an HTTP response header stream that omits the header terminator `\r\n\r\n`.
- The responder keeps the connection open and continues sending full-size blocks.

## Proof

`ocspcheck` extracts the OCSP URL from the certificate and sends the OCSP request through `http_get()`.

Reachability:
- `usr.sbin/ocspcheck/ocspcheck.c:646`
- `usr.sbin/ocspcheck/ocspcheck.c:666`

Propagation:
- `http_get()` calls `http_head_read()` before parsing the body at `usr.sbin/ocspcheck/http.c:692`.

Bug:
- `http_head_read()` reads `BUFSIZ` chunks using `http_read()`.
- Each successful read grows `trans->hbuf` to `trans->hbufsz + ssz` with `realloc()`.
- The new data is copied into `trans->hbuf`.
- The accumulated buffer is searched for `\r\n\r\n`.
- The loop continues while no terminator is found and each read returns a full `BUFSIZ` block.
- No maximum header length is enforced before the patch.

A malicious responder that continuously streams bytes without `\r\n\r\n` drives unbounded heap growth.

## Why This Is A Real Bug

The response stream is controlled by the OCSP responder. `http_head_read()` trusts that the peer will eventually send a valid HTTP header terminator or close the connection. If the peer instead sends full blocks indefinitely, the only practical bound on `trans->hbuf` is available memory.

`OCSP_MAX_RESPONSE_SIZE` does not mitigate this issue because it applies to saved staple input, not network HTTP header buffering.

The impact is attacker-triggered denial of service through memory exhaustion or allocation failure.

## Fix Requirement

Enforce a maximum HTTP header size before growing `trans->hbuf`.

The check must occur before `realloc()` so attacker-controlled input cannot cause heap growth beyond the committed limit.

## Patch Rationale

The patch introduces:

```c
#define HTTP_MAXHEADERLENGTH	(64 * 1024)
```

and rejects any read that would cause `trans->hbufsz + ssz` to exceed that limit:

```c
if ((size_t)ssz > HTTP_MAXHEADERLENGTH - trans->hbufsz) {
	warnx("%s: header too large", http->src.ip);
	return NULL;
}
```

This bounds total buffered header data to 64 KiB and fails closed when a responder exceeds the limit. The arithmetic is structured as a subtraction comparison, avoiding overflow in `trans->hbufsz + ssz`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ocspcheck/http.c b/usr.sbin/ocspcheck/http.c
index 46b01f1..cee75e4 100644
--- a/usr.sbin/ocspcheck/http.c
+++ b/usr.sbin/ocspcheck/http.c
@@ -34,6 +34,8 @@
 
 #include "http.h"
 
+#define HTTP_MAXHEADERLENGTH	(64 * 1024)
+
 /*
  * A buffer for transferring HTTP/S data.
  */
@@ -611,6 +613,10 @@ http_head_read(const struct http *http, struct httpxfer *trans, size_t *sz)
 			return NULL;
 		else if (ssz == 0)
 			break;
+		if ((size_t)ssz > HTTP_MAXHEADERLENGTH - trans->hbufsz) {
+			warnx("%s: header too large", http->src.ip);
+			return NULL;
+		}
 		pp = realloc(trans->hbuf, trans->hbufsz + ssz);
 		if (pp == NULL) {
 			warn("realloc");
```