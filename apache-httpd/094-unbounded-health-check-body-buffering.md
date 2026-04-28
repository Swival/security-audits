# Unbounded Health Check Body Buffering

## Classification

Resource lifecycle bug; high severity; confidence certain.

## Affected Locations

`modules/proxy/mod_proxy_hcheck.c:816`

## Summary

HTTP health checks using GET read backend response bodies into `r->kept_body` without any byte counter or maximum size. A backend that returns a very large or endless body can force the health-check worker/watchdog to retain unbounded memory, and expressions using `HC_BODY` or `HC("BODY")` can trigger an additional full-size flattening allocation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An HTTP health check is configured with GET or GET11.
- The backend returns an unbounded, very large, or continuously streamed response body.
- The check is not header-only, so `hc_check_http()` calls `hc_read_body()`.

## Proof

`hc_check_http()` sends the health-check request, reads headers, and for non-header-only requests calls `hc_read_body()`.

In `hc_read_body()`, backend response bytes enter through:

```c
rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_READBYTES,
                    APR_BLOCK_READ, len);
```

Every non-EOS, non-FLUSH bucket is then removed from the temporary brigade and appended to `r->kept_body`:

```c
APR_BUCKET_REMOVE(bucket);
APR_BRIGADE_INSERT_TAIL(r->kept_body, bucket);
```

The loop continues until EOS or read error. There is no byte counter, configured limit, or discard path. The reproduced analysis also confirms that no upstream response-body limit applies in this path because the HTTP input filter sets `ctx->limit = 0` for proxied responses, so fixed-length, chunked, and close-delimited bodies can all be consumed without a maximum.

If a health-check expression references `HC_BODY` or `HC("BODY")`, `hc_get_body()` computes the brigade length, allocates `len + 1`, and flattens the entire kept brigade, creating an additional allocation proportional to the unbounded body size.

## Why This Is A Real Bug

The vulnerable path is reachable during normal watchdog health checks, not only during client request handling. The memory is retained in the per-check pool until the check completes, so a large finite body can exhaust memory during a single check and an endless stream can keep buffering until read failure or memory exhaustion. Since health checks can run periodically and concurrently through the health-check thread pool, the impact can be amplified across workers.

## Fix Requirement

Enforce a maximum buffered health-check response body size before inserting buckets into `r->kept_body`. If the limit is exceeded, stop reading and fail the health check or discard excess data without retaining it.

## Patch Rationale

The patch introduces `HC_MAX_BODY_SIZE` with a 64 KiB cap and tracks `body_len` inside `hc_read_body()`. Before a bucket is moved into `r->kept_body`, the code reads the bucket length, verifies that adding it would not exceed the cap, and aborts with `APR_ENOSPC` if the cap would be crossed. The loop condition now also requires `rv == APR_SUCCESS`, ensuring limit violations and bucket read failures terminate the read path.

This bounds retained response-body memory and prevents `HC_BODY` / `HC("BODY")` from flattening arbitrarily large kept brigades.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_hcheck.c b/modules/proxy/mod_proxy_hcheck.c
index 70f1de8..0588d69 100644
--- a/modules/proxy/mod_proxy_hcheck.c
+++ b/modules/proxy/mod_proxy_hcheck.c
@@ -26,6 +26,7 @@ module AP_MODULE_DECLARE_DATA proxy_hcheck_module;
 
 #define HCHECK_WATHCHDOG_NAME ("_proxy_hcheck_")
 #define HC_THREADPOOL_SIZE (16)
+#define HC_MAX_BODY_SIZE (64 * 1024)
 
 /* Why? So we can easily set/clear HC_USE_THREADS during dev testing */
 #if APR_HAS_THREADS
@@ -794,10 +795,12 @@ static int hc_read_headers(request_rec *r)
 static int hc_read_body(request_rec *r, apr_bucket_brigade *bb)
 {
     apr_status_t rv = APR_SUCCESS;
+    apr_size_t body_len = 0;
     int seen_eos = 0;
 
     do {
         apr_size_t len = HUGE_STRING_LEN;
+        const char *data;
 
         apr_brigade_cleanup(bb);
         rv = ap_get_brigade(r->proto_input_filters, bb, AP_MODE_READBYTES,
@@ -823,11 +826,20 @@ static int hc_read_body(request_rec *r, apr_bucket_brigade *bb)
                 apr_bucket_delete(bucket);
                 continue;
             }
+            rv = apr_bucket_read(bucket, &data, &len, APR_BLOCK_READ);
+            if (rv != APR_SUCCESS) {
+                break;
+            }
+            if (len > HC_MAX_BODY_SIZE - body_len) {
+                rv = APR_ENOSPC;
+                break;
+            }
+            body_len += len;
             APR_BUCKET_REMOVE(bucket);
             APR_BRIGADE_INSERT_TAIL(r->kept_body, bucket);
         }
     }
-    while (!seen_eos);
+    while (!seen_eos && rv == APR_SUCCESS);
     apr_brigade_cleanup(bb);
     return (rv == APR_SUCCESS ? OK : !OK);
 }
```