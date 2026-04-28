# Malformed Content-Length Forwarded Before Validation

## Classification

Validation gap, medium severity, certain confidence.

## Affected Locations

- `modules/proxy/mod_proxy_ajp.c:236`
- `modules/proxy/mod_proxy_ajp.c:291`
- `modules/proxy/ajp_header.c:101`
- `modules/proxy/ajp_header.c:289`
- `modules/proxy/ajp_header.c:711`

## Summary

`mod_proxy_ajp` forwarded request headers to the AJP backend before validating the client-supplied `Content-Length`. A malformed `Content-Length` could therefore reach the backend in the AJP header packet before the proxy later rejected the request with a client error.

The patch validates `Content-Length` before `ajp_send_header()`, preventing malformed values from being marshalled or sent to the backend.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Client sends a request routed through normal `ajp://` proxy handling.
- Request includes a malformed `Content-Length` header.
- Request has no `Transfer-Encoding` header that would bypass the non-TE `Content-Length` path.

## Proof

A malformed `Content-Length` enters `r->headers_in`.

Before the patch, `ap_proxy_ajp_request()` called `ajp_send_header()` first. That path marshalled the request headers into the AJP packet:

- `modules/proxy/mod_proxy_ajp.c:238` called `ajp_send_header()`.
- `modules/proxy/ajp_header.c:101` mapped `Content-Length` to the AJP compact header code.
- `modules/proxy/ajp_header.c:289` appended the unvalidated header value.
- `modules/proxy/ajp_header.c:711` sent the AJP packet.

Only afterward did the non-`Transfer-Encoding` path validate the same header:

- `modules/proxy/mod_proxy_ajp.c:291` called `get_content_length()`.
- `modules/proxy/mod_proxy_ajp.c:153` set `len = -1` on parse failure.
- `modules/proxy/mod_proxy_ajp.c:306` returned a client error.

Practical trigger: an HTTP/2 request routed to an `ajp://` backend with `content-length: abc` and no `Transfer-Encoding`. The AJP backend receives the malformed `Content-Length` before the proxy returns `400`.

## Why This Is A Real Bug

The proxy’s validation decision occurred after the security-relevant side effect: forwarding client-controlled malformed header data to the backend. This creates inconsistent request interpretation risk between the proxy and AJP backend and violates the expected proxy boundary behavior that malformed request framing metadata is rejected before backend transmission.

The issue is reachable through normal AJP proxy handling and was reproduced.

## Fix Requirement

Validate `Content-Length` before any AJP request header packet is generated or sent. If parsing fails, return `HTTP_BAD_REQUEST` immediately and do not call `ajp_send_header()`.

## Patch Rationale

The patch moves the existing `get_content_length(r)` validation to the start of `ap_proxy_ajp_request()`, before `ajp_send_header()`.

This preserves the existing parser and rejection semantics while changing the order so malformed `Content-Length` is rejected before backend-visible effects occur. The later duplicate validation in the non-`Transfer-Encoding` body-read path is removed because `content_length` has already been validated and retained.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_ajp.c b/modules/proxy/mod_proxy_ajp.c
index 356894a..93f87e1 100644
--- a/modules/proxy/mod_proxy_ajp.c
+++ b/modules/proxy/mod_proxy_ajp.c
@@ -230,6 +230,11 @@ static int ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
     if (*conn->worker->s->secret)
         secret = conn->worker->s->secret;
 
+    content_length = get_content_length(r);
+    if (content_length < 0) {
+        return HTTP_BAD_REQUEST;
+    }
+
     /*
      * Send the AJP request to the remote server
      */
@@ -287,16 +292,9 @@ static int ap_proxy_ajp_request(apr_pool_t *p, request_rec *r,
             return HTTP_INTERNAL_SERVER_ERROR;
         }
     } else {
-        /* Get client provided Content-Length header */
-        content_length = get_content_length(r);
-        if (content_length < 0) {
-            status = APR_EINVAL;
-        }
-        else {
-            status = ap_get_brigade(r->input_filters, input_brigade,
-                                    AP_MODE_READBYTES, APR_BLOCK_READ,
-                                    maxsize - AJP_HEADER_SZ);
-        }
+        status = ap_get_brigade(r->input_filters, input_brigade,
+                                AP_MODE_READBYTES, APR_BLOCK_READ,
+                                maxsize - AJP_HEADER_SZ);
         if (status != APR_SUCCESS) {
             /* We had a failure: Close connection to backend */
             conn->close = 1;
```