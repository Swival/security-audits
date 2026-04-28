# Wrong Filter Checked Before Insertion

## Classification

Logic error, medium severity.

## Affected Locations

`modules/filters/mod_request.c:318`

## Summary

`ap_request_insert_filter()` checks for the wrong input filter before adding `KEEP_BODY`. In the `conf->keep_body` branch, it tests for `KEPT_BODY` but then inserts `KEEP_BODY`, allowing duplicate `KEEP_BODY` filters when one is already present.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `KeptBodySize` is enabled.
- The request already has a `KEEP_BODY` input filter.
- The request does not have a `KEPT_BODY` input filter.
- `r->kept_body` is unset.

## Proof

In `ap_request_insert_filter()`, the `conf->keep_body` branch runs when no kept body exists and body retention is configured:

```c
else if (conf->keep_body) {
    if (!request_is_filter_present(r, kept_body_input_filter_handle)) {
        ap_add_input_filter_handle(keep_body_input_filter_handle,
                                   NULL, r, r->connection);
    }
}
```

The presence check uses `kept_body_input_filter_handle`, but the insertion uses `keep_body_input_filter_handle`.

A practical trigger is:

- Configure `KeptBodySize`.
- Also configure `SetInputFilter KEEP_BODY`.
- Core configured input filters are inserted before `mod_request`'s `APR_HOOK_LAST` insert-filter hook.
- The request already contains `KEEP_BODY`, but not `KEPT_BODY`.
- The wrong presence check returns false.
- `ap_add_input_filter_handle()` adds another `KEEP_BODY`.

`ap_add_input_filter_handle()` allocates and inserts a new filter without duplicate suppression, so the duplicate filter is real.

## Why This Is A Real Bug

The code intends to avoid duplicate insertion by checking whether the filter is already present. However, it checks for a different filter from the one it inserts.

This causes:

- An extra `KEEP_BODY` filter allocation.
- An extra filter invocation on request body reads.
- A duplicate filter remaining for the request lifetime if the body is never read.
- Divergence from the stated insertion guard behavior.

Impact is limited because once the body is read, the second `KEEP_BODY` filter removes itself after observing that `r->kept_body` was already set by the first filter. The duplicate still exists and executes until that point.

## Fix Requirement

Before adding `keep_body_input_filter_handle`, check whether `keep_body_input_filter_handle` is already present.

## Patch Rationale

The patch changes only the mismatched filter handle in the duplicate check:

```diff
-        if (!request_is_filter_present(r, kept_body_input_filter_handle)) {
+        if (!request_is_filter_present(r, keep_body_input_filter_handle)) {
```

This aligns the guard with the filter being inserted. It preserves existing behavior for the `r->kept_body` branch, where `KEPT_BODY` is correctly checked and inserted.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_request.c b/modules/filters/mod_request.c
index 1768edc..fa255bb 100644
--- a/modules/filters/mod_request.c
+++ b/modules/filters/mod_request.c
@@ -302,7 +302,7 @@ static void ap_request_insert_filter(request_rec * r)
         }
     }
     else if (conf->keep_body) {
-        if (!request_is_filter_present(r, kept_body_input_filter_handle)) {
+        if (!request_is_filter_present(r, keep_body_input_filter_handle)) {
             ap_add_input_filter_handle(keep_body_input_filter_handle,
                                        NULL, r, r->connection);
         }
```