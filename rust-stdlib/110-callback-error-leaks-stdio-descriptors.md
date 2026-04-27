# callback error leaks stdio descriptors

## Classification

Resource lifecycle bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/process/unix/fuchsia.rs:110`

## Summary

`Command::do_exec` on Fuchsia forgets child stdio ownership before running `pre_exec` callbacks. If any callback returns `Err`, the function exits before `fdio_spawn_etc` consumes the transfer descriptors, so the parent leaks the already-created child-side stdio descriptors.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A `before_exec` / `pre_exec` closure returns `Err` after stdio setup and spawn action construction succeeds.

## Proof

In `library/std/src/sys/process/unix/fuchsia.rs`, `do_exec` builds transfer actions for stdin, stdout, and stderr, then calls `mem::forget(stdio)` before iterating `self.get_closures()`.

Because the callbacks use `callback()?`, any callback error returns from `do_exec` before `fdio_spawn_etc` is called. At that point, stdio ownership has already been forgotten, so `ChildStdio::Owned(FileDesc)` values are not dropped and `fdio_spawn_etc` never consumes the transfer descriptors.

For inherited stdio, `fdio_fd_clone` and `fdio_fd_create` also create raw descriptors used in transfer actions; those descriptors likewise have no cleanup owner on the callback error path.

A practical trigger is repeatedly spawning a command with piped stdio and a failing callback:

```rust
Command::new("...")
    .stdin(Stdio::piped())
    .pre_exec(|| Err(io::Error::other("stop")))
    .spawn();
```

Each failed spawn leaks the already-created child stdio descriptor in the parent until descriptor or handle exhaustion.

## Why This Is A Real Bug

The leak occurs on a reachable, supported error path: user-provided pre-exec callbacks may return `Err`. The implementation explicitly relies on `fdio_spawn_etc` consuming transferred descriptors, but the early return prevents that consumption after ownership has been suppressed with `mem::forget`.

This violates the expected resource lifecycle: failed spawn attempts should release descriptors created during setup.

## Fix Requirement

Do not forget stdio ownership until all pre-spawn fallible operations that can return before `fdio_spawn_etc` have completed, or otherwise restore/drop ownership on every pre-spawn error path.

## Patch Rationale

The patch moves the callback execution before `mem::forget(stdio)`. If a callback returns `Err`, `stdio` remains owned and normal drop cleanup releases owned descriptors. If callbacks succeed, the code then calls `mem::forget(stdio)` immediately before `fdio_spawn_etc`, preserving the intended behavior that transferred file descriptors are consumed by the spawn call rather than closed by `FileDesc::drop`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/unix/fuchsia.rs b/library/std/src/sys/process/unix/fuchsia.rs
index 3fae5ec1468..9ba8d1cab34 100644
--- a/library/std/src/sys/process/unix/fuchsia.rs
+++ b/library/std/src/sys/process/unix/fuchsia.rs
@@ -102,14 +102,14 @@ unsafe fn do_exec(
         let action3 = make_action(&stdio.stderr, 2)?;
         let actions = [action1, action2, action3];
 
-        // We don't want FileDesc::drop to be called on any stdio. fdio_spawn_etc
-        // always consumes transferred file descriptors.
-        mem::forget(stdio);
-
         for callback in self.get_closures().iter_mut() {
             callback()?;
         }
 
+        // We don't want FileDesc::drop to be called on any stdio. fdio_spawn_etc
+        // always consumes transferred file descriptors.
+        mem::forget(stdio);
+
         let mut process_handle: zx_handle_t = 0;
         zx_cvt(fdio_spawn_etc(
             ZX_HANDLE_INVALID,
```