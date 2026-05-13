# unref nested worker can outlive parent VM

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/jsc/web_worker.rs:786`

## Summary

A nested worker created with `{ ref: false }` could skip the parent event-loop keepalive while still storing the parent VM as a non-owning `BackRef`. If the parent worker exited before the nested worker finished `start_vm`, the child could dereference the freed parent VM and abort the process.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Untrusted JavaScript runs inside a worker.
- That worker can create nested workers.
- The nested worker can opt out of keepalive with `{ ref: false }` or `.unref()`.

## Proof

- `WebWorker::create` stored `parent` as `bun_ptr::BackRef<VirtualMachine>`.
- The keepalive `parent_poll_ref` was skipped when `default_unref` was true.
- The file header explicitly documented that worker parents are detached and nested workers are not stopped when a worker-parent context tears down.
- The nested child later called `self.parent.get()` in `start_vm`.
- The child then read parent VM fields, including uses at `src/jsc/web_worker.rs:844`, `src/jsc/web_worker.rs:882`, `src/jsc/web_worker.rs:886`, `src/jsc/web_worker.rs:923`, and `src/jsc/web_worker.rs:976`.
- `src/jsc/VirtualMachine.rs:3614` also read the parent VM through `worker.parent_vm()`.
- Existing controls did not close the gap: `live_workers::register` only feeds main-thread `terminate_all_and_wait`, and `src/jsc/bindings/webcore/Worker.cpp:523` only handles failure to post the child close event after the parent context is gone.

## Why This Is A Real Bug

The parent VM pointer is non-owning, and the implementation relied on `parent_poll_ref` to preserve the parent lifetime. For nested workers, `{ ref: false }` disabled that lifetime guard even though worker parents are detached and not joined on exit. A malicious worker could spawn an unref nested worker and return immediately, allowing the parent VM to be destroyed while the child still starts and reads parent fields. That is an attacker-triggered process abort/UAF-style denial of service.

## Fix Requirement

Nested workers must not be allowed to drop the parent keepalive while the child may still dereference the parent VM. Either the parent worker must be kept alive until the nested worker close path runs, or nested workers must be terminated/joined before parent VM teardown.

## Patch Rationale

The patch records whether the parent VM belongs to a worker with `parent_ref.worker_ref().is_some()`. For such nested workers, `parent_poll_ref` is always acquired during creation, even when `default_unref` is set. `set_ref(false)` also refuses to unref the parent keepalive for nested workers. This preserves the `BackRef` lifetime invariant without changing main-thread worker unref behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/src/jsc/web_worker.rs b/src/jsc/web_worker.rs
index 5490fe42c5..5cfd9a872c 100644
--- a/src/jsc/web_worker.rs
+++ b/src/jsc/web_worker.rs
@@ -86,13 +86,15 @@ pub struct WebWorker {
     /// Validity: when the parent is the main thread, `globalExit()` calls
     /// `terminateAllAndWait()` before freeing anything, so this stays valid
     /// through `startVM()` even with `{ref:false}`/`.unref()`. When the parent
-    /// is itself a worker, nothing joins us on its exit — the nested-worker
-    /// "Known gap" in the file header. When `parent_poll_ref` is held (the
-    /// default), the parent's loop stays alive until the close task runs.
+    /// is itself a worker, `parent_poll_ref` is always held until the close task
+    /// runs because worker parents are not joined on exit.
     // `BackRef` (not `&'a VirtualMachine`) because the struct is FFI-owned and
     // crosses threads; the backref invariant (parent outlives child via
     // `parent_poll_ref`) is documented above.
     parent: bun_ptr::BackRef<VirtualMachine>,
+    /// True when `parent` is a worker VM. Nested workers must keep their
+    /// parent alive because worker parents are not joined on exit.
+    parent_is_worker: bool,
     parent_context_id: u32,
     execution_context_id: u32,
     mini: bool,
@@ -525,11 +527,13 @@ impl WebWorker {
         }
 
         let store_fd = parent_ref.transpiler.resolver.store_fd;
+        let parent_is_worker = parent_ref.worker_ref().is_some();
 
         let worker = bun_core::heap::into_raw(Box::new(WebWorker {
             cpp_worker,
             // `parent` is the calling thread's live VM; non-null by FFI contract.
             parent: bun_ptr::BackRef::from(NonNull::new(parent).expect("parent VM")),
+            parent_is_worker,
             parent_context_id,
             execution_context_id: this_context_id,
             mini,
@@ -566,9 +570,9 @@ impl WebWorker {
             bun_ptr::ParentRef::from(NonNull::new(worker).expect("heap::into_raw is non-null"));
 
         // Keep the parent's event loop alive until the close task releases this.
-        // If the user passed `{ ref: false }` we skip — they've opted out of the
-        // worker keeping the process alive.
-        if !default_unref {
+        // For nested workers this is required even with `{ ref: false }`: the
+        // child holds a non-owning BackRef to the parent VM.
+        if !default_unref || parent_is_worker {
             // `worker` is a fresh heap allocation; not yet shared.
             // `bun_io::js_vm_ctx()` resolves to this (parent) thread's loop.
             worker_ref.with_parent_poll_ref(|p| p.ref_(bun_io::js_vm_ctx()));
@@ -633,7 +637,8 @@ impl WebWorker {
     /// worker.ref()/.unref() from JS. The struct is guaranteed alive: it's
     /// freed by `~Worker`, which can't run while JSWorker (the caller) holds
     /// its `Ref<Worker>`. `Worker::setKeepAlive()` gates out calls after
-    /// terminate() or the close task, so this can unconditionally toggle.
+    /// terminate() or the close task, so this can toggle unless a nested
+    /// worker needs the parent keep-alive for VM lifetime safety.
     ///
     /// Takes `*mut` (not `&mut`) because the worker thread concurrently
     /// dereferences this struct; materialising `&mut WebWorker` here would be
@@ -645,10 +650,11 @@ impl WebWorker {
         // `bun_io::js_vm_ctx()` resolves to this (parent) thread's loop, which
         // IS `this.parent`'s loop.
         let this = bun_ptr::ParentRef::from(NonNull::new(this).expect("WebWorker FFI ptr"));
+        let parent_is_worker = this.parent_is_worker;
         this.with_parent_poll_ref(|poll| {
             if value {
                 poll.ref_(bun_io::js_vm_ctx());
-            } else {
+            } else if !parent_is_worker {
                 poll.unref(bun_io::js_vm_ctx());
             }
         });
```