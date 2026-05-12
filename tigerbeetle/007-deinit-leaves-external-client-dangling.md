# deinit leaves external client dangling

## Classification

Memory corruption; use-after-free; medium severity. Confidence: certain.

Threat model note: the attacker here is in-process JavaScript that retains and re-invokes the raw N-API exports after `deinit`. The TypeScript wrapper in `index.ts` nulls `context` after close, so the realistic trigger is an application bug (double-`deinit`, or use after close) rather than an external attacker. Impact is heap corruption or crash inside the user's own Node process; not a remote vulnerability, but a real soundness gap in the native boundary and worth fixing.

## Affected Locations

`src/clients/node/node.zig:230`

## Summary

The Node native addon stored a raw `*tb_client.ClientInterface` in a JavaScript external. `deinit` freed that allocation but did not invalidate the external. JavaScript retaining the external could call exported native functions again, causing `deinit` or `submit` to recover and dereference a stale pointer.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Attacker can retain and reuse the external client value returned by the raw addon `init(...)`.
- Attacker can call exported native addon functions directly, bypassing the TypeScript wrapper guard.

## Proof

- `init(...)` returned a JavaScript external containing the native client pointer.
- `deinit(ctx)` called `destroy(...)`, which recovered the pointer with `translate.value_external(...)`.
- `destroy(...)` cast the external value to `*tb_client.ClientInterface`, called `client.deinit()`, and freed it with `global_allocator.destroy(client)`.
- The JavaScript external was not cleared, replaced, or marked closed after the native allocation was freed.
- A second `deinit(ctx)` recovered the same stale pointer and reached `client.completion_context()` on freed memory.
- A later `submit(ctx, ...)` similarly recovered the stale pointer and reached `client.submit(packet)` on freed memory.
- The high-level TypeScript wrapper sets `context = null`, but the native addon exports remain directly callable by JavaScript code that retains the external.

## Why This Is A Real Bug

The lifetime of the JavaScript external outlived the native allocation it referenced. N-API returned the stored pointer unchanged on later calls, so native code dereferenced memory after it had been released. This can crash or corrupt the Node process and is not prevented by the TypeScript wrapper when the raw addon exports are invoked directly.

## Fix Requirement

The external must not continue to expose a freed `ClientInterface` pointer. Reuse after `deinit` must be detected and rejected before dereferencing freed native memory.

## Patch Rationale

The patch stores a stable `ClientContext` in the external instead of storing the client pointer directly:

```zig
const ClientContext = struct {
    client: ?*tb_client.ClientInterface,
};
```

`create(...)` allocates this context and initializes `client` to the live `*tb_client.ClientInterface`.

`destroy(...)` now:

- Recovers the stable `ClientContext`.
- Checks `client_context.client`.
- Returns `ERR_CLIENT_CLOSED` if it is already `null`.
- Sets `client_context.client = null` before deinitializing and freeing the client.

`request(...)` performs the same null check and returns `ERR_CLIENT_CLOSED` instead of calling `client.submit(...)` on freed memory.

This preserves the JavaScript external value while separating it from the freed client allocation and makes repeated `deinit` or post-close `submit` fail safely.

## Residual Risk

Minor memory leak: `translate.create_external` is called with a `null` finalizer (see `src/clients/node/src/translate.zig:139`), so the `ClientContext` struct lives until the napi external is garbage-collected with no associated free. Each `init`/`deinit` cycle therefore leaks one `ClientContext` (a single nullable pointer) until process exit. In typical usage clients are long-lived so this is acceptable; a more thorough fix would register an `napi_create_external` finalizer that frees the context on GC.

## Patch

```diff
diff --git a/src/clients/node/node.zig b/src/clients/node/node.zig
index 4d5716f42..8a9056230 100644
--- a/src/clients/node/node.zig
+++ b/src/clients/node/node.zig
@@ -19,6 +19,10 @@ const stdx = vsr.stdx;
 
 const global_allocator = std.heap.c_allocator;
 
+const ClientContext = struct {
+    client: ?*tb_client.ClientInterface,
+};
+
 pub const std_options: std.Options = .{
     .log_level = .debug,
     .logFn = tb_client.exports.Logging.application_logger,
@@ -217,17 +221,27 @@ fn create(
     };
     errdefer client.deinit() catch unreachable;
 
-    return try translate.create_external(env, client);
+    const client_context = global_allocator.create(ClientContext) catch {
+        return translate.throw(env, .{
+            .message = "Failed to allocate the client context.",
+        });
+    };
+    errdefer global_allocator.destroy(client_context);
+    client_context.* = .{ .client = client };
+
+    return try translate.create_external(env, client_context);
 }
 
 // Javascript is single threaded so no synchronization is necessary for closing/accessing a client.
 fn destroy(env: c.napi_env, context: c.napi_value) !void {
-    const client_ptr = try translate.value_external(
+    const context_ptr = try translate.value_external(
         env,
         context,
         "Failed to get client context pointer.",
     );
-    const client: *tb_client.ClientInterface = @ptrCast(@alignCast(client_ptr.?));
+    const client_context: *ClientContext = @ptrCast(@alignCast(context_ptr.?));
+    const client = client_context.client orelse return request_error(env, .ERR_CLIENT_CLOSED);
+    client_context.client = null;
     defer {
         client.deinit() catch unreachable;
         global_allocator.destroy(client);
@@ -251,12 +265,13 @@ fn request(
     array: c.napi_value,
     callback: c.napi_value,
 ) !void {
-    const client_ptr = try translate.value_external(
+    const context_ptr = try translate.value_external(
         env,
         context,
         "Failed to get client context pointer.",
     );
-    const client: *tb_client.ClientInterface = @ptrCast(@alignCast(client_ptr.?));
+    const client_context: *ClientContext = @ptrCast(@alignCast(context_ptr.?));
+    const client = client_context.client orelse return request_error(env, .ERR_CLIENT_CLOSED);
 
     // Create a reference to the callback so it stay alive until the packet completes.
     var callback_ref: c.napi_ref = undefined;
```