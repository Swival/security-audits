# Transfer-Encoding and Content-Length Forwarded After Chunked Selection

## Classification

High severity request smuggling.

Confidence: certain.

## Affected Locations

`usr.sbin/relayd/relay_http.c:524`

`usr.sbin/relayd/relay_http.c:1325`

## Summary

`relayd` accepts requests containing both `Transfer-Encoding: chunked` and `Content-Length`, selects chunked parsing internally, but forwards both original framing headers to the backend. If the backend honors `Content-Length` over `Transfer-Encoding`, relayd and the backend disagree about request boundaries, allowing a smuggled request inside chunk data to bypass relayd HTTP filters.

## Provenance

Verified by reproduced finding from Swival Security Scanner: https://swival.dev

## Preconditions

- A remote HTTP client can send a request through relayd.
- The request contains both `Transfer-Encoding: chunked` and `Content-Length`.
- The backend honors `Content-Length` over `Transfer-Encoding` on forwarded requests.

## Proof

`relay_read_http` processes headers one at a time. For `Content-Length`, it sets `cre->toread` from the attacker-controlled value. For `Transfer-Encoding: chunked`, it only sets `desc->http_chunked = 1`.

After header filtering, `desc->http_chunked` overrides body handling:

```c
if (desc->http_chunked) {
	/* Chunked transfer encoding */
	cre->toread = TOREAD_HTTP_CHUNK_LENGTH;
	bev->readcb = relay_read_httpchunks;
}
```

The original headers remain stored in `desc->http_headers`. `relay_writeheader_http` then iterates and writes every stored header to the backend, so both framing headers are forwarded.

Concrete trigger:

```http
POST /allowed HTTP/1.1\r
Host: v\r
Transfer-Encoding: chunked\r
Content-Length: 4\r
\r
33\r
GET /admin HTTP/1.1\r
Host: v\r
Content-Length: 7\r
\r
\r
0\r
\r
```

`relayd` parses this as one chunked `POST /allowed` request and treats the embedded `GET /admin` bytes as chunk data. A `Content-Length`-preferring backend consumes `33\r\n` as the first request body, then parses `GET /admin HTTP/1.1` as the next request.

## Why This Is A Real Bug

The relay applies HTTP filters before chunk parsing completes, so the embedded request is not evaluated as an HTTP request by relayd. Because both `Transfer-Encoding` and `Content-Length` are forwarded, backend framing can diverge from relayd framing. That creates a request smuggling primitive where attacker-controlled bytes reach backend request parsing past relayd’s path and header filters.

## Fix Requirement

When `Transfer-Encoding` is present and selected for chunked processing, relayd must not forward `Content-Length` to the backend. It must either reject such requests or remove `Content-Length` before forwarding.

## Patch Rationale

The patch removes `Content-Length` from forwarded headers whenever `desc->http_chunked` is set. This preserves relayd’s selected chunked framing on the backend-facing request and prevents a `Content-Length`-preferring backend from using a conflicting message boundary.

The change is applied at header serialization time in `relay_writeheader_http`, which is the point where stored headers are emitted to the backend. It avoids forwarding stale, attacker-supplied `Content-Length` values after chunked parsing has already been selected.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/relayd/relay_http.c b/usr.sbin/relayd/relay_http.c
index d6960e8..c458d59 100644
--- a/usr.sbin/relayd/relay_http.c
+++ b/usr.sbin/relayd/relay_http.c
@@ -1323,6 +1323,9 @@ relay_writeheader_http(struct ctl_relay_event *dst, struct ctl_relay_event
 	struct http_descriptor	*desc = (struct http_descriptor *)cre->desc;
 
 	RB_FOREACH(hdr, kvtree, &desc->http_headers) {
+		if (desc->http_chunked &&
+		    strcasecmp(hdr->kv_key, "Content-Length") == 0)
+			continue;
 		if (relay_writeheader_kv(dst, hdr) == -1)
 			return (-1);
 		TAILQ_FOREACH(kv, &hdr->kv_children, kv_entry) {
```