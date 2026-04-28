# FIFO Termination Does Not Wake Blocked Waiters

## Classification

Resource lifecycle bug, medium severity.

## Affected Locations

`modules/http2/h2_proxy_util.c:1169`

## Summary

`h2_proxy_fifo_term()` marks the FIFO as aborted but does not wake threads already blocked on the FIFO condition variables. A blocked puller waits on `not_empty`, and a blocked pusher waits on `not_full`; both only observe `fifo->aborted` after their condition wait returns. Without broadcasts during termination, those threads can remain asleep indefinitely instead of returning `APR_EOF`.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A thread is blocked in FIFO pull while the FIFO is empty.
- Or a thread is blocked in FIFO push while the FIFO is full.
- `h2_proxy_fifo_term()` is called while that thread is already waiting.

## Proof

`h2_proxy_fifo_term()` acquires `fifo->lock`, sets `fifo->aborted = 1`, and unlocks. It does not broadcast `fifo->not_empty` or `fifo->not_full`.

A blocked puller in `check_not_empty()` waits while `fifo->count == 0` and only checks `fifo->aborted` before calling `apr_thread_cond_wait(fifo->not_empty, fifo->lock)` again. If termination happens after the waiter sleeps, there is no termination wakeup on `not_empty`.

A blocked pusher in `fifo_push()` waits while `fifo->count == fifo->nelems` and only checks `fifo->aborted` before calling `apr_thread_cond_wait(fifo->not_full, fifo->lock)` again. If termination happens after the waiter sleeps, there is no termination wakeup on `not_full`.

The intended wake pattern is already present in `h2_proxy_fifo_interrupt()`, which broadcasts both condition variables while holding the same lock.

## Why This Is A Real Bug

The abort flag alone is insufficient because condition waiters do not poll it asynchronously. They re-check `fifo->aborted` only after waking from `apr_thread_cond_wait()`. If termination sets the flag without signaling, a waiter blocked before termination can remain blocked forever. This causes shutdown or teardown paths to hang instead of allowing waiting FIFO operations to return `APR_EOF`.

## Fix Requirement

After setting `fifo->aborted = 1`, `h2_proxy_fifo_term()` must broadcast both FIFO condition variables while still holding `fifo->lock`.

## Patch Rationale

Broadcasting `not_empty` wakes blocked pullers so they can re-check `fifo->aborted` and return `APR_EOF`.

Broadcasting `not_full` wakes blocked pushers so they can re-check `fifo->aborted` and return `APR_EOF`.

Holding `fifo->lock` while setting the flag and broadcasting preserves the existing synchronization discipline and matches `h2_proxy_fifo_interrupt()`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_proxy_util.c b/modules/http2/h2_proxy_util.c
index bb384b9..56133f7 100644
--- a/modules/http2/h2_proxy_util.c
+++ b/modules/http2/h2_proxy_util.c
@@ -1174,6 +1174,8 @@ apr_status_t h2_proxy_fifo_term(h2_proxy_fifo *fifo)
     apr_status_t rv;
     if ((rv = apr_thread_mutex_lock(fifo->lock)) == APR_SUCCESS) {
         fifo->aborted = 1;
+        apr_thread_cond_broadcast(fifo->not_empty);
+        apr_thread_cond_broadcast(fifo->not_full);
         apr_thread_mutex_unlock(fifo->lock);
     }
     return rv;
```