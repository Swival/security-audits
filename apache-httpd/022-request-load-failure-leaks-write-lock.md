# Request Load Failure Leaks Write Lock

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`modules/arch/win32/mod_isapi.c:447`

## Summary

A request-time ISAPI DLL load failure leaves the per-DLL `in_progress` rwlock write-locked. The failed DLL remains cached for retry, but the lock is never released on the failure path, causing later same-DLL waiters or retry attempts to block indefinitely.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A request reaches `isapi_handler`.
- The request filename is a previously unseen ISAPI DLL path.
- `isapi_lookup(..., r != NULL, ...)` creates and write-locks `(*isa)->in_progress`.
- `isapi_load` fails for that DLL.

## Proof

- For a previously unseen DLL and `r != NULL`, `isapi_lookup` creates `(*isa)->in_progress` and immediately takes its write lock before inserting the entry into `loaded.hash`.
- After releasing `loaded.lock`, it calls `isapi_load`.
- On failure, `last_load_time` and `last_load_rv` are stored.
- The only original request-time unlock branch was `if (r && (rv == APR_SUCCESS))`.
- Therefore, when `r != NULL` and `rv != APR_SUCCESS`, no branch unlocks `(*isa)->in_progress`.
- Later requests for the same DLL can block on `apr_thread_rwlock_rdlock(gainlock)` while the first load is in progress.
- After `ISAPI_RETRY`, retrying requests can block on `apr_thread_rwlock_wrlock(gainlock)` because the failed initial request still holds the write lock.

## Why This Is A Real Bug

The lock lifetime is intended to cover only the active load attempt. The failed load result is already retained through `last_load_rv` and `last_load_time`, and the `in_progress` lock must remain available for future retry coordination. Holding the write lock after failure makes the cached failed-DLL entry process-persistent and blocks same-DLL request threads, turning a load error into a denial of service for that ISAPI path.

## Fix Requirement

Always unlock `(*isa)->in_progress` after a request-time load attempt completes. On success, also set `(*isa)->in_progress = NULL` because no retry lock is needed. On failure, keep `(*isa)->in_progress` allocated but unlocked so later retry paths can acquire it.

## Patch Rationale

The patch changes the request-time completion branch from success-only to all request-time attempts:

- `if (r && (rv == APR_SUCCESS))` becomes `if (r)`.
- The rwlock is always unlocked for request-time loads.
- `(*isa)->in_progress = NULL` remains limited to `rv == APR_SUCCESS`.
- Failed request-time loads retain the rwlock for later retry coordination without leaving it held.

This preserves the existing retry design while fixing the missing unlock on failure.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/arch/win32/mod_isapi.c b/modules/arch/win32/mod_isapi.c
index a9816e5..8381fb4 100644
--- a/modules/arch/win32/mod_isapi.c
+++ b/modules/arch/win32/mod_isapi.c
@@ -447,12 +447,14 @@ apr_status_t isapi_lookup(apr_pool_t *p, server_rec *s, request_rec *r,
     (*isa)->last_load_time = apr_time_now();
     (*isa)->last_load_rv = rv;
 
-    if (r && (rv == APR_SUCCESS)) {
+    if (r) {
         /* Let others who are blocked on this particular
          * module resume their requests, for better or worse.
          */
         apr_thread_rwlock_t *unlock = (*isa)->in_progress;
-        (*isa)->in_progress = NULL;
+        if (rv == APR_SUCCESS) {
+            (*isa)->in_progress = NULL;
+        }
         apr_thread_rwlock_unlock(unlock);
     }
     else if (!r && (rv != APR_SUCCESS)) {
```