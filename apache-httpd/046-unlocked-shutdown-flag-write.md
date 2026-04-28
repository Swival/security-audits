# Unlocked Shutdown Flag Write

## Classification

Race condition; medium severity. Confidence: certain.

## Affected Locations

`modules/http2/h2_mplx.c:531`

## Summary

`h2_mplx_c1_destroy()` wrote shared shutdown state before acquiring `m->lock`. Other mplx worker/session paths read the same fields while holding `m->lock`, so teardown could race with worker scheduling and polling code on plain non-atomic `int` fields.

## Provenance

Verified from supplied source, reproducer notes, and patch. Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Connection teardown overlaps another mplx worker/session callback.

## Proof

- `h2_mplx_c1_destroy()` set `m->shutdown = m->aborted = 1` before `H2_MPLX_ENTER_ALWAYS(m)`.
- `m->shutdown` and `m->aborted` are plain shared fields, not atomics.
- `c2_prod_next()` reads `m->aborted` under `m->lock`, then may call `s_next_c2()`, which also gates scheduling on `!m->aborted`.
- `h2_mplx_c1_poll()` reads `m->aborted` under `m->lock`.
- `mplx_pollset_poll()` reads `m->shutdown` after reacquiring `m->lock`.
- A valid interleaving exists where a worker holds `m->lock` in `c2_prod_next()` while teardown writes the flags without that lock.

## Why This Is A Real Bug

The file documents that `h2_mplx` calls are protected by `m->lock`. The affected flags are shared between teardown, worker production, and polling paths. Writing them outside the mutex while other threads read them under the mutex creates an unsynchronized conflicting access to non-atomic state. In C this is a data race and undefined behavior; practically, a worker can observe stale shutdown state and dequeue/start another secondary connection after teardown has logically begun.

## Fix Requirement

Acquire `m->lock` before setting `m->shutdown` and `m->aborted` in `h2_mplx_c1_destroy()`.

## Patch Rationale

The patch moves `H2_MPLX_ENTER_ALWAYS(m)` before the shutdown flag assignment. This makes the teardown writes use the same mutex discipline as the existing readers, restoring the shared-state invariant without changing shutdown semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_mplx.c b/modules/http2/h2_mplx.c
index f9616ab..8ca8391 100644
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
```