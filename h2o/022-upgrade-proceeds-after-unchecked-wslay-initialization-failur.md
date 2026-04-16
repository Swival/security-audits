# Upgrade continues after failed wslay context init

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/websocket.c:119`
- `lib/websocket.c:137`
- `lib/websocket.c:221`
- `lib/websocket.c:222`
- `lib/websocket.c:230`
- `lib/websocket.c:231`
- `lib/websocket.c:243`
- `lib/websocket.c:245`

## Summary
`h2o_upgrade_to_websocket` called `wslay_event_context_server_init(&conn->ws_ctx, ...)` and ignored its return value. If initialization failed, the code still completed the HTTP `101` upgrade and `on_complete` still invoked `h2o_websocket_proceed(conn)`. That path unconditionally used `conn->ws_ctx`, making failed initialization reachable and causing a null or invalid context dereference during websocket processing.

## Provenance
- Verified and reproduced from the supplied finding and reproducer
- Source: `lib/websocket.c`
- Scanner reference: https://swival.dev

## Preconditions
- `wslay_event_context_server_init` fails during a WebSocket upgrade
- The HTTP upgrade path otherwise reaches `on_complete`

## Proof
- In `lib/websocket.c:119`, `h2o_upgrade_to_websocket` initialized `conn` and called `wslay_event_context_server_init(&conn->ws_ctx, ...)` without checking the return value.
- In `lib/websocket.c:137`, `on_complete` unconditionally called `h2o_websocket_proceed(conn)` after sending the `101 Switching Protocols` response.
- In `lib/websocket.c:221`, `lib/websocket.c:222`, `lib/websocket.c:230`, `lib/websocket.c:231`, `lib/websocket.c:243`, and `lib/websocket.c:245`, `h2o_websocket_proceed` passed `conn->ws_ctx` into `wslay_event_want_write`, `wslay_event_send`, `wslay_event_want_read`, and `wslay_event_recv` without validating the context.
- Upstream wslay dereferences the context in these helpers without a null guard, so an initialization failure remains exploitable as soon as websocket processing begins.

## Why This Is A Real Bug
This is a concrete denial-of-service condition, not a theoretical invariant violation. The failure path is directly reachable under allocator failure or memory pressure: the server upgrades the connection despite lacking a valid websocket parser state, then immediately dereferences that invalid state in the post-upgrade processing callback. The result is process crash or abort rather than a safe handshake failure.

## Fix Requirement
Check the return value of `wslay_event_context_server_init`. If initialization fails, abort the upgrade before sending `101`, free the partially constructed websocket connection, and ensure websocket processing is never scheduled for that connection.

## Patch Rationale
The patch gates the upgrade on successful wslay context creation. On failure, it releases the allocated `conn` and exits the upgrade path before `on_complete` can call `h2o_websocket_proceed`. This restores the required invariant that every path reaching websocket processing has a valid initialized `ws_ctx`.

## Residual Risk
None

## Patch
```patch
*** Begin Patch
*** Add File: 022-upgrade-proceeds-after-unchecked-wslay-initialization-failur.patch
+diff --git a/lib/websocket.c b/lib/websocket.c
+index 0000000..0000000 100644
+--- a/lib/websocket.c
++++ b/lib/websocket.c
+@@
+     conn = h2o_mem_alloc(sizeof(*conn));
+     memset(conn, 0, sizeof(*conn));
+     conn->sock = sock;
+     conn->sock->data = conn;
+     conn->super.ctx = ctx;
+     conn->super.host = host;
+     conn->super.upgrade.cb = on_ws_message;
+     conn->super.write_frame = enqueue_send;
+     conn->super.set_timeout.cb = set_timeout;
+     conn->ws_callbacks.recv_callback = on_frame_recv_callback;
+     conn->ws_callbacks.send_callback = on_frame_send_callback;
+     conn->ws_callbacks.genmask_callback = NULL;
+-    wslay_event_context_server_init(&conn->ws_ctx, &conn->ws_callbacks, conn, &wslay_config);
++    if (wslay_event_context_server_init(&conn->ws_ctx, &conn->ws_callbacks, conn, &wslay_config) != 0) {
++        free(conn);
++        return;
++    }
+ 
+     h2o_http1_upgrade(req, NULL, 0, on_complete);
*** End Patch
```