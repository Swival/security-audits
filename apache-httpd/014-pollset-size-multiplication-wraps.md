# pollset size multiplication wraps

## Classification

validation gap; medium severity; confidence certain

## Affected Locations

`server/mpm/event/event.c:2327`

## Summary

`AsyncRequestWorkerFactor` accepted extremely large numeric values without an upper bound. The value was scaled into `worker_factor`, later reduced to `async_factor`, and used in:

```c
(apr_uint32_t)num_listensocks +
(apr_uint32_t)threads_per_child * (async_factor > 2 ? async_factor : 2)
```

That 32-bit unsigned multiplication/addition could wrap, causing `event_pollset` to be created smaller than the configured async concurrency.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Administrator configures a very large `AsyncRequestWorkerFactor` value.
- The event MPM is used.
- Runtime reaches `setup_threads_runtime()` and creates the shared `event_pollset`.

## Proof

`set_worker_factor()` parses `AsyncRequestWorkerFactor` with `strtod()` and previously assigned `worker_factor = val * WORKER_FACTOR_SCALE` without an upper bound.

`setup_threads_runtime()` then computes:

```c
const apr_uint32_t async_factor = worker_factor / WORKER_FACTOR_SCALE;
const apr_uint32_t pollset_size = (apr_uint32_t)num_listensocks +
                                  (apr_uint32_t)threads_per_child *
                                  (async_factor > 2 ? async_factor : 2);
```

The reproduced arithmetic showed wraparound:

```text
worker_factor=2748779072 async_factor=171798692 intended=4294967301 pollset_size=5
```

The wrapped `pollset_size` is passed to `apr_pollset_create_ex()` / `apr_pollset_create()`, creating an undersized pollset for the configured concurrency.

## Why This Is A Real Bug

Connections transitioning to async wait, write completion, keepalive, or lingering close are added to `event_pollset`. If the backend enforces the requested pollset capacity, normal client keepalive/async activity can exhaust the undersized pollset, trigger existing `apr_pollset_add()` failure paths, close connections, and call `signal_threads(ST_GRACEFUL)`.

This is not only a numeric correctness issue: it can degrade availability under a valid-but-extreme administrator configuration.

## Fix Requirement

Reject `AsyncRequestWorkerFactor` values that can make the later pollset size arithmetic exceed safe `apr_uint32_t` bounds before assigning `worker_factor`.

## Patch Rationale

The patch adds an upper-bound validation in `set_worker_factor()`:

```c
if (val > (double)(APR_UINT32_MAX - INT_MAX - 1) / MAX_THREAD_LIMIT)
    return "AsyncRequestWorkerFactor argument is too large";
```

This bounds the configured factor before it reaches `worker_factor`, using the maximum possible `threads_per_child` (`MAX_THREAD_LIMIT`) and reserving space for listener sockets plus the wakeable pollset slot. It prevents the later `threads_per_child * async_factor` computation from wrapping in the worst supported configuration.

The patch also changes `val <= 0` to `!(val > 0)`, which rejects NaN as non-positive input instead of letting it bypass the positivity check.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/event/event.c b/server/mpm/event/event.c
index 050d823..7e493fd 100644
--- a/server/mpm/event/event.c
+++ b/server/mpm/event/event.c
@@ -4116,9 +4116,12 @@ static const char *set_worker_factor(cmd_parms * cmd, void *dummy,
     if (*endptr)
         return "error parsing value";
 
-    if (val <= 0)
+    if (!(val > 0))
         return "AsyncRequestWorkerFactor argument must be a positive number";
 
+    if (val > (double)(APR_UINT32_MAX - INT_MAX - 1) / MAX_THREAD_LIMIT)
+        return "AsyncRequestWorkerFactor argument is too large";
+
     worker_factor = val * WORKER_FACTOR_SCALE;
     if (worker_factor < WORKER_FACTOR_SCALE) {
         worker_factor = WORKER_FACTOR_SCALE;
```