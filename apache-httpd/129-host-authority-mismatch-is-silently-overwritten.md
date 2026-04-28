# Host authority mismatch is silently overwritten

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`modules/http2/h2_request.c:208`

## Summary

HTTP/2 requests containing both `:authority` and a different `Host` header were accepted. The request finalization path rewrote `Host` to `:authority` before core request validation, hiding the original mismatch from later routing and module logic.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

An HTTP/2 client sends a request with:

- A populated `:authority` pseudo-header
- A `Host` header
- Different values for `:authority` and `Host`

## Proof

The inbound request path stores client-controlled pseudo-header and regular-header values separately:

- `:authority` populates `req->authority`
- `Host` is stored in `req->headers`

During `h2_request_end_headers()`, when `req->authority` exists, the old behavior unconditionally executed:

```c
apr_table_setn(req->headers, "Host", req->authority);
```

This overwrote the client-supplied `Host` value before later request construction.

The acceptance path then continued:

- `h2_stream_end_headers()` accepted the rewritten request and published it as `stream->request`
- `h2_create_request_rec()` called `assign_headers()`
- `assign_headers()`, `ap_parse_request_line()`, and `ap_check_request_header()` validated only the normalized `Host`

As a result, the malformed mismatch was accepted after being rewritten to `:authority`. The original `Host` was not reliably preserved because `assign_headers()` reads `orig_host` from `req->headers` after `h2_request_end_headers()` has already overwritten it.

## Why This Is A Real Bug

The source comment in `assign_headers()` states that mismatches between `:authority` and `Host` SHOULD be rejected as malformed. The actual behavior did the opposite: it silently normalized the request by overwriting `Host`.

This creates a validation gap because downstream request validation, virtual host selection, and modules observe only the rewritten `Host` value and cannot detect that the original client request contained conflicting authority information.

## Fix Requirement

Reject requests with differing `Host` and `:authority` values before overwriting or normalizing the `Host` header.

## Patch Rationale

The patch adds the missing comparison in `h2_request_end_headers()` before `Host` is rewritten. If both values are present and differ, the function returns `APR_BADARG`, causing the malformed request to be rejected instead of accepted and normalized.

This places validation at the earliest point where both original values are still available.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_request.c b/modules/http2/h2_request.c
index 6373e0a..e8b2863 100644
--- a/modules/http2/h2_request.c
+++ b/modules/http2/h2_request.c
@@ -210,6 +210,10 @@ apr_status_t h2_request_end_headers(h2_request *req, apr_pool_t *pool,
         req->authority = host;
     }
     else {
+        const char *host = apr_table_get(req->headers, "Host");
+        if (host && strcmp(req->authority, host)) {
+            return APR_BADARG;
+        }
         apr_table_setn(req->headers, "Host", req->authority);
     }
     req->raw_bytes += raw_bytes;
```