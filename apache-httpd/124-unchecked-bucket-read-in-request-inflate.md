# Unchecked Bucket Read In Request Inflate

## Classification

Error-handling bug, medium severity.

## Affected Locations

`modules/filters/mod_deflate.c:1375`

## Summary

`deflate_in_filter()` inflated gzip-encoded request bodies after `check_gzip()` removed `Content-Encoding`, but it did not check the return value from `apr_bucket_read()` before using `data` and `len`. If a bucket read failed, those outputs were not proven valid and could be passed into zlib as inflate input state.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The request body is gzip-encoded.
- The request reaches `deflate_in_filter()`.
- An upstream bucket read fails on the request-body path.

## Proof

The reproduced path shows request-body gzip data reaches the inflate loop after `check_gzip()` strips `Content-Encoding`.

In the request inflate loop:

- `apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ)` was called without checking its status.
- `len` was tested immediately after the unchecked call.
- If `len > APR_INT32_MAX`, a second `apr_bucket_read()` was also called without checking its status.
- `data` and `len` were assigned to `ctx->stream.next_in` and `ctx->stream.avail_in`.
- zlib then consumed those values via `inflate(&ctx->stream, Z_NO_FLUSH)`.

On read failure, APR does not guarantee valid `data` and `len` outputs. The code therefore allowed stale or invalid input state to flow into decompression.

## Why This Is A Real Bug

This is a reachable filter-stack error path, not a theoretical API misuse.

The same source tree contains bucket read implementations that can return failure for I/O or filter errors. Neighboring code in the output deflate path correctly checks `apr_bucket_read()` before using its outputs, demonstrating the expected handling pattern.

The request inflate path lacked that check and continued into decompression state setup.

## Fix Requirement

Check every `apr_bucket_read()` result in the request inflate path. If the read fails, stop processing before using `data` or `len`, clean up the zlib stream, and propagate the APR error.

## Patch Rationale

The patch stores the return value from both `apr_bucket_read()` calls in `rv`, verifies `rv == APR_SUCCESS`, calls `inflateEnd(&ctx->stream)` on failure, and returns the original APR error.

This preserves the existing success-path behavior while ensuring invalid bucket-read outputs are never consumed by zlib.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_deflate.c b/modules/filters/mod_deflate.c
index 5a541e7..e8c5614 100644
--- a/modules/filters/mod_deflate.c
+++ b/modules/filters/mod_deflate.c
@@ -1372,13 +1372,21 @@ static apr_status_t deflate_in_filter(ap_filter_t *f,
             }
 
             /* read */
-            apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
+            rv = apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
+            if (rv != APR_SUCCESS) {
+                inflateEnd(&ctx->stream);
+                return rv;
+            }
             if (!len) {
                 continue;
             }
             if (len > APR_INT32_MAX) {
                 apr_bucket_split(bkt, APR_INT32_MAX);
-                apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
+                rv = apr_bucket_read(bkt, &data, &len, APR_BLOCK_READ);
+                if (rv != APR_SUCCESS) {
+                    inflateEnd(&ctx->stream);
+                    return rv;
+                }
             }
 
             if (ctx->zlib_flags) {
```