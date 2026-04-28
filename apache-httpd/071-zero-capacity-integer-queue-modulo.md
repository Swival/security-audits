# Zero-Capacity Integer Queue Modulo

## Classification

Invariant violation, medium severity.

Confidence: certain.

## Affected Locations

`modules/http2/h2_util.c:366`

## Summary

Creating an HTTP/2 integer queue with capacity `0` leaves `q->nalloc == 0`. The first insertion then computes an index with `% q->nalloc`, causing division by zero / undefined behavior and a likely crash.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller creates an `h2_iqueue` with capacity `0`, then adds an id through the public queue API.

Minimal trigger:

```c
h2_iqueue *q = h2_iq_create(pool, 0);
h2_iq_append(q, 1);
```

## Proof

`h2_iq_create(pool, 0)` calls `iq_grow(q, capacity)` with `capacity == 0`.

`iq_grow()` only allocates when `nlen > q->nalloc`. Since both are `0`, it does not allocate and leaves:

```c
q->elts == NULL
q->nalloc == 0
q->nelts == 0
```

On the first add, `h2_iq_contains()` does not enter its loop because `q->nelts == 0`, so no earlier modulo executes.

`h2_iq_add()` then evaluates:

```c
if (q->nelts >= q->nalloc) {
    iq_grow(q, q->nalloc * 2);
}
i = (q->head + q->nelts) % q->nalloc;
```

With `q->nelts == 0` and `q->nalloc == 0`, the grow request is still `0`, remains a no-op, and the subsequent modulo divides by zero.

## Why This Is A Real Bug

The queue API accepts the invalid state through public functions: `h2_iq_create()` permits capacity `0`, and `h2_iq_append()` / `h2_iq_add()` are sufficient to reach the modulo operation deterministically.

This violates the queue invariant that `q->nalloc` must be positive before any modulo-based ring-buffer operation. The observed effect is undefined behavior, typically a `SIGFPE` crash.

No default in-tree configuration path was identified that sets existing `H2MaxSessionStreams` callers to zero, because `h2_conf_set_max_streams()` rejects values `< 1` at `modules/http2/h2_config.c:594`. That does not invalidate the bug: the public queue API itself admits the zero-capacity state.

## Fix Requirement

Ensure every created `h2_iqueue` has positive storage capacity before insertion can occur.

Acceptable fixes include rejecting nonpositive capacity or normalizing the initial capacity to at least `1`.

## Patch Rationale

The patch normalizes `capacity <= 0` to `1` inside `h2_iq_create()`:

```c
iq_grow(q, capacity > 0? capacity : 1);
```

This preserves existing behavior for valid positive capacities and prevents `q->nalloc` from remaining zero after construction. As a result, the first `h2_iq_add()` cannot compute modulo zero.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_util.c b/modules/http2/h2_util.c
index b377ff7..0bc4a69 100644
--- a/modules/http2/h2_util.c
+++ b/modules/http2/h2_util.c
@@ -335,7 +335,7 @@ h2_iqueue *h2_iq_create(apr_pool_t *pool, int capacity)
 {
     h2_iqueue *q = apr_pcalloc(pool, sizeof(h2_iqueue));
     q->pool = pool;
-    iq_grow(q, capacity);
+    iq_grow(q, capacity > 0? capacity : 1);
     q->nelts = 0;
     return q;
 }
```