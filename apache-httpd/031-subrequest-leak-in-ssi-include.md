# SSI Include Subrequest Pool Leak

## Classification

Resource lifecycle bug; severity: medium; confidence: certain.

## Affected Locations

`modules/filters/mod_include.c:1455`

`modules/filters/mod_include.c:1880`

`modules/filters/mod_include.c:1899`

## Summary

`handle_include()` creates SSI include subrequests for `virtual`, `file`, and `onerror` attributes, runs them with `ap_run_sub_req()`, and then intentionally does not call `ap_destroy_sub_req(rr)`. Each subrequest owns a dedicated pool, so every processed include retains its subrequest pool and associated allocations until the parent request is torn down.

## Provenance

Verified from the supplied source, reproduced lifecycle trace, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An SSI `include` directive with a `virtual`, `file`, or `onerror` attribute is processed.

## Proof

SSI input reaches `handle_include()` through `include_handlers` registered for `"include"`.

For each processed include attribute, `handle_include()` creates a subrequest using one of:

- `ap_sub_req_lookup_file()`
- `ap_sub_req_lookup_uri()`
- `ap_sub_req_method_uri()`

The subrequest is optionally executed through `ap_run_sub_req(rr)`.

The original code then skips `ap_destroy_sub_req(rr)` and documents the leak explicitly:

```c
/* Do *not* destroy the subrequest here; it may have allocated
 * variables in this r->subprocess_env in the subrequest's
 * r->pool, so that pool must survive as long as this request.
 * Yes, this is a memory leak. */
```

The reproduced trace confirms that `make_sub_request()` creates a dedicated child pool for each subrequest at `server/request.c:2021`, and `ap_destroy_sub_req()` would reclaim it by destroying `r->pool` at `server/request.c:2547`.

## Why This Is A Real Bug

The lifecycle contract is violated: subrequests allocated for SSI includes are not destroyed after use. The retained child pools keep request, filter, module, and environment-related allocations alive for the remainder of the parent request.

A single SSI response containing many include directives or attributes can accumulate one retained subrequest pool per processed include. The leak is bounded by parent request lifetime, but it creates avoidable per-request memory pressure and can be amplified by large or attacker-controlled SSI documents.

## Fix Requirement

Before destroying each include subrequest, preserve any needed environment table data that may point into the subrequest pool by copying it into the parent/main request pool. Then call `ap_destroy_sub_req(rr)` on every created subrequest, including error paths.

## Patch Rationale

The patch replaces the intentional non-destruction with explicit ownership transfer for `r->subprocess_env` entries:

- It walks to the top-level request pool, matching the lifetime used elsewhere for SSI environment state.
- It duplicates every environment key into that stable pool.
- It duplicates every non-null, non-`LAZY_VALUE` environment value into that stable pool.
- It then calls `ap_destroy_sub_req(rr)`, allowing the subrequest pool and resources to be reclaimed.
- It defers breaking after an `onerror` failure with `break_after_error`, ensuring cleanup still runs before exiting the loop.

This preserves the stated reason for the original leak workaround while restoring the missing subrequest lifecycle cleanup.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_include.c b/modules/filters/mod_include.c
index 2c0cc67..bbec90b 100644
--- a/modules/filters/mod_include.c
+++ b/modules/filters/mod_include.c
@@ -1814,6 +1814,7 @@ static apr_status_t handle_include(include_ctx_t *ctx, ap_filter_t *f,
         char *parsed_string;
         apr_status_t rv = APR_SUCCESS;
         int status = 0;
+        int break_after_error = 0;
 
         ap_ssi_get_tag_and_value(ctx, &tag, &tag_val, SSI_VALUE_DECODED);
         if (!tag || !tag_val) {
@@ -1888,7 +1889,7 @@ static apr_status_t handle_include(include_ctx_t *ctx, ap_filter_t *f,
                     r->filename, status ? status : rr ? rr->status : 0);
             if (last_error) {
                 /* onerror threw an error, give up completely */
-                break;
+                break_after_error = 1;
             }
             last_error = error_fmt;
         }
@@ -1896,10 +1897,31 @@ static apr_status_t handle_include(include_ctx_t *ctx, ap_filter_t *f,
             last_error = NULL;
         }
 
-        /* Do *not* destroy the subrequest here; it may have allocated
-         * variables in this r->subprocess_env in the subrequest's
-         * r->pool, so that pool must survive as long as this request.
-         * Yes, this is a memory leak. */
+        if (rr) {
+            const apr_array_header_t *arr = apr_table_elts(r->subprocess_env);
+            apr_table_entry_t *elts = (apr_table_entry_t *)arr->elts;
+            request_rec *sub = r->main;
+            apr_pool_t *p = r->pool;
+            int i;
+
+            while (sub) {
+                p = sub->pool;
+                sub = sub->main;
+            }
+
+            for (i = 0; i < arr->nelts; ++i) {
+                elts[i].key = apr_pstrdup(p, elts[i].key);
+                if (elts[i].val && elts[i].val != LAZY_VALUE) {
+                    elts[i].val = apr_pstrdup(p, elts[i].val);
+                }
+            }
+
+            ap_destroy_sub_req(rr);
+        }
+
+        if (break_after_error) {
+            break;
+        }
 
     }
```