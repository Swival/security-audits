# Transaction Pool Leak On Queue Failure

## Classification

Resource lifecycle bug. Severity: low. Confidence: certain.

## Affected Locations

`server/mpm/worker/worker.c:691`

## Summary

The worker MPM listener can leak a per-transaction pool when an accepted socket cannot be queued to a worker. On `ap_queue_push_socket()` failure, the code closes the accepted socket and logs the failure, but leaves `ptrans` neither destroyed nor returned to the idle pool. The next listener loop overwrites the local `ptrans` pointer, making the pool unreachable until process exit.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

An accepted connection exists and `ap_queue_push_socket(worker_queue, csd, NULL, ptrans)` returns an error before successfully transferring ownership of `ptrans` to the worker queue.

## Proof

`listener_thread` obtains a recycled transaction pool with `ap_queue_info_pop_pool(worker_queue_info, &ptrans)` or creates a new one before accept. `lr->accept_func(&csd, lr, ptrans)` stores the accepted connection state using that pool. If `csd != NULL`, the listener attempts to transfer the socket and pool to workers through `ap_queue_push_socket(worker_queue, csd, NULL, ptrans)`.

On failure, the affected code only executes:

```c
apr_socket_close(csd);
ap_log_error(..., "ap_queue_push_socket failed");
```

It does not clear, destroy, or recycle `ptrans`.

On the next loop, `ap_queue_info_pop_pool(worker_queue_info, &ptrans)` overwrites the local pointer. The reproduced analysis also confirms the callee first sets the output to `NULL`, so the previous transaction pool becomes unreachable. `ap_queue_info_free_idle_pools()` only frees pools still present on the recycled idle-pool list and therefore cannot recover this lost pool.

## Why This Is A Real Bug

The transaction pool has a defined lifecycle: it is either transferred to a worker on successful queue insertion, cleared by the worker after connection processing, and later recycled; or it must be explicitly handled by the listener on failure. The worker MPM failure path did neither.

The event MPM analogous path recycles `ptrans` on queue-push failure, confirming that returning the pool to the idle pool is the expected lifecycle behavior. This leak is reachable whenever queue insertion fails after accept and leaks one transaction pool per trigger.

## Fix Requirement

On `ap_queue_push_socket()` failure after an accepted connection, the listener must release ownership of `ptrans` by either clearing/destroying it or returning it to the idle pool.

## Patch Rationale

The patch returns `ptrans` to `worker_queue_info` with `ap_queue_info_push_pool(worker_queue_info, ptrans)` immediately after closing the unqueued socket. This preserves the existing pool-reuse model used by the worker MPM and avoids destroying a reusable transaction pool unnecessarily.

The call is placed only in the queue-failure branch, where the listener still owns `ptrans` because the socket and pool were not successfully handed off to a worker.

## Residual Risk

None

## Patch

```diff
diff --git a/server/mpm/worker/worker.c b/server/mpm/worker/worker.c
index 315371d..38e5682 100644
--- a/server/mpm/worker/worker.c
+++ b/server/mpm/worker/worker.c
@@ -693,6 +693,7 @@ static void * APR_THREAD_FUNC listener_thread(apr_thread_t *thd, void * dummy)
                      * socket to a worker
                      */
                     apr_socket_close(csd);
+                    ap_queue_info_push_pool(worker_queue_info, ptrans);
                     ap_log_error(APLOG_MARK, APLOG_CRIT, rv, ap_server_conf, APLOGNO(03138)
                                  "ap_queue_push_socket failed");
                 }
```