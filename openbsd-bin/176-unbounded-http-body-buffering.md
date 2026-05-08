# Unbounded HTTP Body Buffering

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.sbin/ocspcheck/http.c:419`

## Summary

`ocspcheck` buffered HTTP response bodies without any maximum size. A malicious OCSP or HTTP responder could stream full `BUFSIZ` chunks indefinitely, causing `http_body_read()` to repeatedly grow `trans->bbuf` until allocation failure or process memory exhaustion.

## Provenance

Reproduced and patched from the verified finding. Scanner provenance: Swival Security Scanner, https://swival.dev

## Preconditions

`ocspcheck` connects to an attacker-controlled OCSP responder or HTTP endpoint.

## Proof

`ocspcheck` reaches the vulnerable path when it fetches the certificate OCSP URL via `http_get()` in `usr.sbin/ocspcheck/ocspcheck.c:666`.

After headers are read, `http_get()` calls `http_body_read()` in `usr.sbin/ocspcheck/http.c:696` before validating the HTTP status code or OCSP response contents.

`http_body_read()` repeatedly calls `http_read()` with a `BUFSIZ` stack buffer. For each nonzero read, it grows `trans->bbuf` with:

```c
recallocarray(trans->bbuf, trans->bbufsz, trans->bbufsz + ssz, 1)
```

The loop continues while the read size equals `BUFSIZ`. No `Content-Length` limit, OCSP response limit, or other maximum body size is enforced on the network response path.

A malicious responder can return valid HTTP headers followed by endless full-size body chunks. This forces unbounded allocation growth until memory exhaustion, causing an attacker-triggered denial of service.

## Why This Is A Real Bug

The vulnerable allocation occurs before response validation, so the attacker only needs to control the responder stream, not produce a valid OCSP response.

The existing `OCSP_MAX_RESPONSE_SIZE` limit only applies to local `-i` staple-file reads in `usr.sbin/ocspcheck/ocspcheck.c:720`. It does not constrain HTTP response bodies read by `http_body_read()`.

## Fix Requirement

Enforce a maximum HTTP response body size before reallocating or copying additional response body data.

## Patch Rationale

The patch defines `HTTP_MAX_BODY_SIZE` as `20 * 1024`, matching the OCSP response size class expected by this utility.

Before `recallocarray()`, `http_body_read()` now checks whether appending the latest chunk would exceed the maximum body size. The check also avoids unsigned underflow by first rejecting already oversized `trans->bbufsz`.

If the limit would be exceeded, the function emits `body too large` and returns `NULL`, preventing further allocation growth.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ocspcheck/http.c b/usr.sbin/ocspcheck/http.c
index 46b01f1..914d315 100644
--- a/usr.sbin/ocspcheck/http.c
+++ b/usr.sbin/ocspcheck/http.c
@@ -34,6 +34,8 @@
 
 #include "http.h"
 
+#define HTTP_MAX_BODY_SIZE	(20 * 1024)
+
 /*
  * A buffer for transferring HTTP/S data.
  */
@@ -416,6 +418,11 @@ http_body_read(const struct http *http, struct httpxfer *trans, size_t *sz)
 		else if (ssz == 0)
 			break;
 
+		if (trans->bbufsz > HTTP_MAX_BODY_SIZE ||
+		    (size_t)ssz > HTTP_MAX_BODY_SIZE - trans->bbufsz) {
+			warnx("%s: body too large", http->src.ip);
+			return NULL;
+		}
 		pp = recallocarray(trans->bbuf,
 		    trans->bbufsz, trans->bbufsz + ssz, 1);
 		if (pp == NULL) {
```