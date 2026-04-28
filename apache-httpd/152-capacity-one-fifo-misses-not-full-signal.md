# Capacity-One FIFO Misses `not_full` Signal

## Classification

Race condition, medium severity. Confidence: certain.

## Affected Locations

`modules/http2/h2_proxy_util.c:1270`

## Summary

`pull_head()` only broadcasts `not_full` inside a branch that requires the post-decrement FIFO count to remain positive. For a capacity-one FIFO, pulling the only element changes `count` from `1` to `0`, skips that branch, and never wakes producers blocked on `not_full`.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

A capacity-one FIFO has a blocked producer and a consumer pulls the sole element.

## Proof

`h2_proxy_fifo_push()` waits on `not_full` while `fifo->count == fifo->nelems`.

When a consumer calls `h2_proxy_fifo_pull()`, it reaches `pull_head()`:

- `pull_head()` decrements `fifo->count` from `1` to `0`.
- The existing code only checks whether the FIFO was previously full inside `if (fifo->count > 0)`.
- For capacity one, `fifo->count > 0` is false after the decrement.
- Therefore `apr_thread_cond_broadcast(fifo->not_full)` is skipped.
- The blocked producer remains asleep even though capacity is now available.

The public API exposes this path. `h2_proxy_fifo_create()` forwards capacity directly to `create_int()` and does not reject capacity `1`; blocking push and pull APIs are publicly declared.

## Why This Is A Real Bug

This is a missed wakeup on the condition variable protecting FIFO capacity. The state transition from full to not-full is exactly the condition producers are waiting for, but the notification is omitted for the capacity-one case. The result can be an indefinite hang or deadlock unless an unrelated interrupt, broadcast, or spurious wakeup occurs.

For larger full FIFOs, decrementing from `nelems` to `nelems - 1` leaves `fifo->count > 0`, so the old code reaches the broadcast check. Capacity-one queues are the edge case where the post-decrement count is zero and the notification is lost.

## Fix Requirement

Broadcast `not_full` whenever the queue was full before decrementing `count`, independent of whether elements remain after the pull.

## Patch Rationale

The patch moves the fullness-transition check outside the `if (fifo->count > 0)` block.

This preserves the existing head-advance behavior, which is only needed when elements remain, while ensuring `not_full` is broadcast for every transition from full to not-full, including `1 -> 0`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_proxy_util.c b/modules/http2/h2_proxy_util.c
index bb384b9..a239b00 100644
--- a/modules/http2/h2_proxy_util.c
+++ b/modules/http2/h2_proxy_util.c
@@ -1276,9 +1276,9 @@ static void *pull_head(h2_proxy_fifo *fifo)
     --fifo->count;
     if (fifo->count > 0) {
         fifo->head = nth_index(fifo, 1);
-        if (fifo->count+1 == fifo->nelems) {
-            apr_thread_cond_broadcast(fifo->not_full);
-        }
+    }
+    if (fifo->count+1 == fifo->nelems) {
+        apr_thread_cond_broadcast(fifo->not_full);
     }
     return elem;
 }
```