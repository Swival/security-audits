# Unchecked Bucket Read In Proxy Inflate

## Classification

error-handling bug, medium severity, confidence: certain

## Affected Locations

`modules/filters/mod_deflate.c:1743`

## Summary

`inflate_out_filter()` ignored the return value from `apr_bucket_read()` while processing gzip response buckets for the `INFLATE` output filter. If a bucket read failed, the filter still used `data` and `len`, which were not proven valid after failure. This could cause stale or uninitialized values to drive gzip parsing, copying, or zlib input handling.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The `INFLATE` output filter processes gzip content.
- An upstream response bucket read fails while the filter is inflating the response body.
- The failed bucket read occurs before `inflate_out_filter()` validates or consumes `data`/`len`.

## Proof

The reproduced path shows that response body data reaches `inflate_out_filter()` through bucket brigades. The `INFLATE` output filter is registered as a normal output filter at `modules/filters/mod_deflate.c:1913`.

A CGI/gateway response that sets `Content-Encoding: gzip` and then stalls or errors after headers can reach `ap_pass_brigade(r->output_filters, bb)` at `modules/generators/cgi_common.h:521`. `inflate_out_filter()` then consumes the remaining CGI bucket.

At the proxy inflate read site, the vulnerable code called:

```c
apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
```

and immediately used `len` and `data`:

```c
if (!len) {
    apr_bucket_delete(e);
    continue;
}
if (len > APR_INT32_MAX) {
    apr_bucket_split(e, APR_INT32_MAX);
    apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
}
```

Because the return status was ignored, a failed read did not stop processing. `len` and `data` could therefore remain stale or uninitialized and later be passed into `memcpy()` or zlib inflate processing.

## Why This Is A Real Bug

`apr_bucket_read()` communicates read failure through its `apr_status_t` return value. The bucket API does not guarantee that output parameters are valid after a failed read. Continuing to branch on `len`, split buckets, copy from `data`, or pass `data` to zlib after failure violates that API contract.

The reproduced reachability confirms this is not dead code: gzip-encoded upstream response data can flow through the registered `INFLATE` output filter. On read failure, the bug can drop the error, parse invalid lengths, copy from an invalid pointer, feed invalid input to zlib, fail the request incorrectly, or crash a worker, producing denial of service.

## Fix Requirement

Check every `apr_bucket_read()` return value in the affected `inflate_out_filter()` read path. If the read fails, abort processing and propagate the non-success status before using `data` or `len`.

## Patch Rationale

The patch stores the result of each `apr_bucket_read()` call in `rv` and immediately returns on failure. This matches the existing safe pattern used elsewhere in `mod_deflate.c`, including the deflate output path, and preserves normal behavior for successful reads.

The second read after `apr_bucket_split()` is also checked, because it has the same API contract and can independently fail.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_deflate.c b/modules/filters/mod_deflate.c
index 5a541e7..ce7e0de 100644
--- a/modules/filters/mod_deflate.c
+++ b/modules/filters/mod_deflate.c
@@ -1740,14 +1740,20 @@ static apr_status_t inflate_out_filter(ap_filter_t *f,
         }
 
         /* read */
-        apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
+        rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
+        if (rv != APR_SUCCESS) {
+            return rv;
+        }
         if (!len) {
             apr_bucket_delete(e);
             continue;
         }
         if (len > APR_INT32_MAX) {
             apr_bucket_split(e, APR_INT32_MAX);
-            apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
+            rv = apr_bucket_read(e, &data, &len, APR_BLOCK_READ);
+            if (rv != APR_SUCCESS) {
+                return rv;
+            }
         }
 
         /* first bucket contains zlib header */
```