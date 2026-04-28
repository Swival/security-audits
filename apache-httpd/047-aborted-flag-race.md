# Aborted Flag Race

## Classification

Race condition, medium severity. Confidence: certain.

## Affected Locations

`modules/http2/h2_mplx.c:1053`

## Summary

`workers_shutdown()` wrote `m->shutdown` and `m->aborted` while holding only `m->poll_lock`, but other HTTP/2 mplx paths read those fields while holding `m->lock`. Because the fields are non-atomic and protected by inconsistent mutexes, concurrent shutdown and stream processing can produce a C data race with undefined behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Workers shutdown runs concurrently with code reading `m->aborted` or `m->shutdown` under `m->lock`.

## Proof

`workers_shutdown()` is registered by `h2_mplx_c1_create()` as the worker shutdown callback with the mplx baton. During child shutdown, worker shutdown can run while HTTP/2 connection/session processing is still active.

Before the patch, `workers_shutdown()` did this under `m->poll_lock` only:

```c
m->shutdown = 1;
if (!graceful) {
    m->aborted = 1;
}
```

Other paths read these fields under `m->lock`, including:

- `h2_mplx_c1_poll()` reads `m->aborted`
- `h2_mplx_c1_reprioritize()` reads `m->aborted`
- `c1_process_stream()` reads `m->aborted`
- `c2_prod_next()` reads `m->aborted`
- `mplx_pollset_poll()` reads `m->shutdown` and `m->aborted`

Since the writer and readers do not synchronize on the same mutex and the fields are not atomic, there is no happens-before relationship. A practical path exists when `h2_workers_shutdown()` invokes `workers_shutdown()` for an idle HTTP/2 producer while the c1/session path is polling or scheduling streams.

## Why This Is A Real Bug

This is a real C data race, not just a logical ordering issue. Concurrent non-atomic access to `m->aborted` or `m->shutdown`, where at least one access is a write and no common synchronization protects the accesses, is undefined behavior.

The direct behavioral impact is inconsistent shutdown handling. The c1/session path may miss or mis-handle the abort transition, continue scheduling or polling streams instead of returning `APR_ECONNABORTED`, or treat an ungraceful shutdown as a graceful wakeup in `mplx_pollset_poll()`.

## Fix Requirement

Protect `m->aborted` and `m->shutdown` consistently with `m->lock`, or convert all accesses to atomic operations with correct ordering.

## Patch Rationale

The patch standardizes protection of `m->shutdown` and `m->aborted` on `m->lock`.

In `workers_shutdown()`, the patch acquires `m->lock` before writing either field, then wakes the pollset under `m->poll_lock`, and finally releases `m->lock`. This aligns the writer with existing readers that already hold `m->lock`.

In `h2_mplx_c1_destroy()`, the patch moves `H2_MPLX_ENTER_ALWAYS(m)` before setting `m->shutdown = m->aborted = 1`, removing another unsynchronized write to the same fields.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_mplx.c b/modules/http2/h2_mplx.c
index f9616ab..872df44 100644
--- a/modules/http2/h2_mplx.c
+++ b/modules/http2/h2_mplx.c
@@ -501,12 +501,12 @@ void h2_mplx_c1_destroy(h2_mplx *m)
 
     ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
                   H2_MPLX_MSG(m, "start release"));
+    H2_MPLX_ENTER_ALWAYS(m);
+
     /* How to shut down a h2 connection:
      * 0. abort and tell the workers that no more work will come from us */
     m->shutdown = m->aborted = 1;
 
-    H2_MPLX_ENTER_ALWAYS(m);
-
     /* While really terminating any c2 connections, treat the master
      * connection as aborted. It's not as if we could send any more data
      * at this point. */
@@ -1054,16 +1054,18 @@ static void workers_shutdown(void *baton, int graceful)
 {
     h2_mplx *m = baton;
 
-    apr_thread_mutex_lock(m->poll_lock);
-    /* time to wakeup and assess what to do */
-    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
-                  H2_MPLX_MSG(m, "workers shutdown, waking pollset"));
+    H2_MPLX_ENTER_ALWAYS(m);
     m->shutdown = 1;
     if (!graceful) {
         m->aborted = 1;
     }
+    apr_thread_mutex_lock(m->poll_lock);
+    /* time to wakeup and assess what to do */
+    ap_log_cerror(APLOG_MARK, APLOG_TRACE2, 0, m->c1,
+                  H2_MPLX_MSG(m, "workers shutdown, waking pollset"));
     apr_pollset_wakeup(m->pollset);
     apr_thread_mutex_unlock(m->poll_lock);
+    H2_MPLX_LEAVE(m);
 }
 
 /*******************************************************************************
```