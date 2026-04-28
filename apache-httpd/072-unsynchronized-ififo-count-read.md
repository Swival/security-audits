# Unsynchronized `h2_ififo_count` Read

## Classification

Race condition, low severity.

Confidence: certain.

## Affected Locations

`modules/http2/h2_util.c:958`

## Summary

`h2_ififo_count()` returned `fifo->count` without holding `fifo->lock`, while other `h2_ififo` operations update the same field under that mutex. Concurrent callers could therefore trigger a C data race and observe stale or inconsistent queue state through the exported count API.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

Multiple threads access the same `h2_ififo` concurrently, with at least one thread calling `h2_ififo_count()` while another mutates the queue through `h2_ififo_push()`, `h2_ififo_pull()`, or `h2_ififo_remove()`.

## Proof

`h2_ififo_count()` directly returned `fifo->count` at `modules/http2/h2_util.c:958` without acquiring `fifo->lock`.

The same field is modified while holding `fifo->lock` in the integer FIFO mutation paths:

- `h2_ififo_push()` locks before calling `ififo_push_int()`, which increments `fifo->count`.
- `h2_ififo_pull()` locks before calling `ipull_head()`, which decrements `fifo->count`.
- `h2_ififo_remove()` locks before calling `ififo_remove()`, which subtracts removed entries from `fifo->count`.

The pointer FIFO analogue, `h2_fifo_count()`, already takes `fifo->lock` before reading its `count` field, showing the intended synchronization pattern.

## Why This Is A Real Bug

The queue implementation treats `count` as mutex-protected shared state. Reading it outside the mutex while other threads write it inside the mutex violates that synchronization invariant and creates an unsynchronized read/write race in C.

The race is reachable through the exported `h2_ififo_count()` API whenever callers share one `h2_ififo` across threads.

## Fix Requirement

Guard the `fifo->count` read in `h2_ififo_count()` with `fifo->lock`, matching the existing `h2_fifo_count()` implementation.

## Patch Rationale

The patch adds a local temporary, locks `fifo->lock`, copies `fifo->count`, unlocks the mutex, and returns the copied value.

This makes reads of `count` use the same synchronization discipline as writes, removes the data race, and preserves the function’s public behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_util.c b/modules/http2/h2_util.c
index b377ff7..7a9e17b 100644
--- a/modules/http2/h2_util.c
+++ b/modules/http2/h2_util.c
@@ -953,7 +953,12 @@ apr_status_t h2_ififo_term(h2_ififo *fifo)
 
 int h2_ififo_count(h2_ififo *fifo)
 {
-    return fifo->count;
+    int n;
+
+    apr_thread_mutex_lock(fifo->lock);
+    n = fifo->count;
+    apr_thread_mutex_unlock(fifo->lock);
+    return n;
 }
 
 static apr_status_t icheck_not_empty(h2_ififo *fifo, int block)
```