# request-close use-after-free in status collection

## Classification

Memory corruption / use-after-free. Severity: high. Confidence: certain.

## Affected Locations

- `lib/handler/status.c:163`
- `on_req_json`
- `collect_reqs_of_context`
- `on_req_close`
- `on_collector_dispose`

## Summary

The status JSON handler stores `collector->status_ctx.entries` in the request pool while the collector itself is shared across asynchronous multithread status collection messages. If the client closes the request before collection completes, request disposal frees the request pool, but queued status collection messages still hold and use the collector. Those messages later dereference `collector->status_ctx.entries`, producing a request-close use-after-free.

## Provenance

Verified and patched from a Swival.dev Security Scanner finding: https://swival.dev

## Preconditions

- The status handler is enabled.
- The `/json` status endpoint is reachable by a remote client.

## Proof

Trigger sequence:

1. A remote client requests the status JSON endpoint, e.g. `/json`.
2. `on_req_json` allocates `collector` as shared memory.
3. `on_req_json` grows `collector->status_ctx` with:

   ```c
   h2o_vector_reserve(&req->pool, &collector->status_ctx, collector->status_ctx.size + 1);
   ```

   Therefore `collector->status_ctx.entries` is backed by `req->pool`.
4. `on_req_json` queues collection messages to all status receivers.
5. Before the queued messages complete, the client aborts the request. A deterministic HTTP/2 trigger is to send `RST_STREAM` immediately after the `/json` request HEADERS.
6. Request disposal clears `req->pool`, invalidating `collector->status_ctx.entries`.
7. `on_req_close` only sets:

   ```c
   collector->src.req = NULL;
   ```

   and releases its shared reference. The collector can remain alive because queued multithread messages still reference it.
8. A queued receiver later runs `collect_reqs_of_context`, which dereferences the freed vector storage:

   ```c
   struct st_status_ctx_t *sc = collector->status_ctx.entries + i;
   ```

9. The stale `active` and `ctx` fields are then used to decide whether to call `sh->per_thread(sc->ctx, ctx)`.

Impact: a remote client with access to the status endpoint can trigger use-after-free in server code, causing crash or memory corruption.

## Why This Is A Real Bug

The collector lifetime intentionally extends beyond the request lifetime: it is allocated with `h2o_mem_alloc_shared` and referenced by queued multithread messages. However, one of its fields, `status_ctx.entries`, is allocated from `req->pool`, whose lifetime ends when the request is closed.

`send_response` checks `collector->src.req` and exits if the request is gone, but this check occurs too late. The use-after-free occurs earlier in `collect_reqs_of_context`, before the completion path reaches `send_response`.

Thus request cancellation can free memory that is still reachable and dereferenced by outstanding status collection work.

## Fix Requirement

`collector->status_ctx.entries` must have the same effective lifetime as `collector`, not the request. It must not be allocated from `req->pool`. The vector storage should be heap-backed and released when the collector is disposed.

## Patch Rationale

The patch changes `h2o_vector_reserve` to use `NULL` as the memory pool, causing `status_ctx.entries` to be heap allocated instead of request-pool allocated. It also frees that heap allocation in `on_collector_dispose`.

This aligns the vector storage lifetime with the shared collector lifetime. If the request closes early, `collector->src.req` is still nulled and the response is skipped, but outstanding collection messages can safely read `collector->status_ctx.entries` until the collector’s final shared reference is released.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/handler/status.c b/lib/handler/status.c
index 16db48bcd..1595b025e 100644
--- a/lib/handler/status.c
+++ b/lib/handler/status.c
@@ -143,6 +143,8 @@ static void on_collect_notify(h2o_multithread_receiver_t *receiver, h2o_linklist
 
 static void on_collector_dispose(void *_collector)
 {
+    struct st_h2o_status_collector_t *collector = _collector;
+    free(collector->status_ctx.entries);
 }
 
 static void on_req_close(void *p)
@@ -163,7 +165,7 @@ static int on_req_json(struct st_h2o_root_status_handler_t *self, h2o_req_t *req
         for (i = 0; i < req->conn->ctx->globalconf->statuses.size; i++) {
             h2o_status_handler_t *sh;
 
-            h2o_vector_reserve(&req->pool, &collector->status_ctx, collector->status_ctx.size + 1);
+            h2o_vector_reserve(NULL, &collector->status_ctx, collector->status_ctx.size + 1);
             sh = req->conn->ctx->globalconf->statuses.entries[i];
 
             if (status_list.base) {
```