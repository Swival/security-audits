# Unbounded Response Body Exhausts Memory

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/acme-client/http.c:398`

## Summary

`http_body_read` appended every received body chunk to `trans->bbuf` without enforcing a maximum response size. An attacker-controlled ACME HTTPS endpoint could send valid headers followed by indefinitely large full `BUFSIZ` body chunks, forcing unbounded heap growth until allocation failure or memory pressure prevented certificate renewal.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

The client connects to an attacker-controlled or compromised ACME endpoint.

## Proof

`http_get` reads response headers and then calls `http_body_read`.

In `http_body_read`, each `http_read` result is appended to the accumulated body:

- `recallocarray(trans->bbuf, trans->bbufsz, trans->bbufsz + ssz, 1)` grows the heap buffer.
- `memcpy(trans->bbuf + trans->bbufsz, buf, ssz)` copies attacker-controlled response bytes.
- `trans->bbufsz += ssz` records the new accumulated size.
- The loop continues while `ssz == sizeof(buf)`.

There was no `Content-Length` enforcement and no maximum body-size check before reallocating. A malicious HTTPS server could therefore keep sending full `BUFSIZ` chunks, causing unbounded memory growth. A large finite body also propagates onward and is copied again in `netproc`.

## Why This Is A Real Bug

The vulnerable loop’s termination depends on EOF, read error, zero-length read, or a short read. A peer that controls the HTTPS response can avoid those conditions while repeatedly returning full chunks. Because each chunk triggers a larger allocation and copy, memory consumption is attacker-controlled and unbounded. This can exhaust process or system memory and prevent ACME certificate renewal.

## Fix Requirement

Reject responses before reallocating when the accumulated body would exceed a fixed maximum response body size.

## Patch Rationale

The patch defines `HTTP_BODY_MAX` as 1 MiB and checks the next append before calling `recallocarray`. The check also guards against size arithmetic overflow by comparing `trans->bbufsz` with `HTTP_BODY_MAX - (size_t)ssz`. If the response body would exceed the limit, the client logs `HTTP body too large` and fails the transfer instead of growing memory further.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/acme-client/http.c b/usr.sbin/acme-client/http.c
index 1d745ce..e4214ac 100644
--- a/usr.sbin/acme-client/http.c
+++ b/usr.sbin/acme-client/http.c
@@ -62,6 +62,8 @@ struct	http {
 	struct tls	  *ctx;    /* TLS context */
 };
 
+#define HTTP_BODY_MAX	((size_t)1024 * 1024)
+
 struct tls_config *tlscfg;
 
 static ssize_t
@@ -401,6 +403,11 @@ http_body_read(const struct http *http, struct httpxfer *trans, size_t *sz)
 			return NULL;
 		else if (ssz == 0)
 			break;
+		if ((size_t)ssz > HTTP_BODY_MAX ||
+		    trans->bbufsz > HTTP_BODY_MAX - (size_t)ssz) {
+			warnx("%s: HTTP body too large", http->src.ip);
+			return NULL;
+		}
 		pp = recallocarray(trans->bbuf,
 		    trans->bbufsz, trans->bbufsz + ssz, 1);
 		if (pp == NULL) {
```