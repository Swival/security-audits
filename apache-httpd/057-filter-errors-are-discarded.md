# filter errors are discarded

## Classification

Error-handling bug, medium severity, certain confidence.

## Affected Locations

`modules/filters/mod_ext_filter.c:895`

## Summary

`ef_output_filter()` logs failures from `ef_unified_filter()` but continues to call `ap_pass_brigade()`. The later assignment overwrites the original filter failure, so a successful downstream brigade pass makes `ef_output_filter()` return `APR_SUCCESS` even though external filtering failed.

## Provenance

Verified and reproduced from supplied source and patch context. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An output `ExtFilter` is configured.
- `ef_unified_filter(f, bb)` returns a non-success status.
- `ap_pass_brigade(f->next, bb)` returns `APR_SUCCESS`.

## Proof

In `ef_output_filter()`, the return value from `ef_unified_filter(f, bb)` is assigned to `rv`. If `rv != APR_SUCCESS`, the code logs `"ef_unified_filter() failed"` but does not return.

Execution then reaches:

```c
if ((rv = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
```

This overwrites the earlier filtering error. If `ap_pass_brigade()` succeeds, the function returns `APR_SUCCESS`, hiding the failed filter operation from callers.

A concrete source-grounded path is a child filter process closing or failing stdin: `pass_data_to_filter()` logs and returns the write error, `ef_unified_filter()` propagates it, then `ef_output_filter()` logs and discards it if downstream passing succeeds.

## Why This Is A Real Bug

The function contract is broken because a failed external output filter can be reported as success. This prevents callers and higher-level request handling from detecting that filtering failed. For failures before the brigade cleanup point in `ef_unified_filter()`, the original or partially processed brigade may also continue downstream despite the filter error.

## Fix Requirement

`ef_output_filter()` must preserve and return the `ef_unified_filter()` error. It must not overwrite that error with the result of `ap_pass_brigade()`.

## Patch Rationale

The patch returns immediately after logging a non-success result from `ef_unified_filter()`. This preserves the original failure status and prevents downstream brigade passing from masking the failed filtering operation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_ext_filter.c b/modules/filters/mod_ext_filter.c
index 6a7c9e4..3eaf8d2 100644
--- a/modules/filters/mod_ext_filter.c
+++ b/modules/filters/mod_ext_filter.c
@@ -880,6 +880,7 @@ static apr_status_t ef_output_filter(ap_filter_t *f, apr_bucket_brigade *bb)
     if (rv != APR_SUCCESS) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01468)
                       "ef_unified_filter() failed");
+        return rv;
     }
 
     if ((rv = ap_pass_brigade(f->next, bb)) != APR_SUCCESS) {
```