# Cloned Handle Leaked On fd Creation Error

## Classification

Resource lifecycle bug, medium severity.

## Affected Locations

`library/std/src/sys/process/unix/fuchsia.rs:88`

## Summary

Fuchsia process spawning cloned a Zircon handle with `fdio_fd_clone`, then returned early if `fdio_fd_create` failed. The early return bypassed any cleanup for the cloned handle, leaking it in the parent process during failed `Command::spawn` setup.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `Command::spawn` reaches Fuchsia stdio setup through `setup_io` and unsafe `do_exec`.
- `make_action` handles a child stdio entry where `local_io.fd()` is absent and the entry is not `ChildStdio::Null`.
- `fdio_fd_clone(target_fd, &mut handle)` succeeds and stores a valid cloned handle.
- `fdio_fd_create(handle, &mut cloned_fd)` fails before ownership of the handle is converted into a file descriptor.

## Proof

In `make_action`, the affected branch initializes `handle` and calls:

```rust
let status = fdio_fd_clone(target_fd, &mut handle);
...
zx_cvt(status)?;

let mut cloned_fd = 0;
zx_cvt(fdio_fd_create(handle, &mut cloned_fd))?;
```

If `fdio_fd_clone` succeeds, `handle` contains a live cloned Zircon handle. If `fdio_fd_create` then fails, the `?` returns immediately from `make_action` without calling `zx_handle_close(handle)`.

This path is reachable from `Command::spawn` through `setup_io` and `do_exec`. The stdio actions are built sequentially for stdin, stdout, and stderr. A practical trigger is inherited stdio where cloning and creating an earlier action succeeds, but a later `fdio_fd_create` fails, for example due to file descriptor allocation failure after the first cloned fd consumes the last available descriptor slot.

## Why This Is A Real Bug

The cloned handle is not wrapped in an RAII owner before `fdio_fd_create`. On the failing path, no `FileDesc`, `Handle`, `fdio_spawn_action_t`, or `stdio` owner is responsible for closing it. Since `fdio_spawn_etc` is not reached, it cannot consume the action. Dropping `stdio` also cannot close this cloned handle because it was created independently by `fdio_fd_clone`.

The result is a leaked kernel handle in the parent process whenever `fdio_fd_clone` succeeds and `fdio_fd_create` fails.

## Fix Requirement

Close the cloned handle if `fdio_fd_create` returns an error, or transfer it into an RAII wrapper before any fallible conversion that can return early.

## Patch Rationale

The patch stores the `fdio_fd_create` status, explicitly closes `handle` when the status is negative, and only then converts the status with `zx_cvt(status)?`.

This preserves the success path: on success, `fdio_fd_create` consumes the handle and returns a valid cloned file descriptor. On failure, the still-owned cloned handle is closed before returning the error.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/unix/fuchsia.rs b/library/std/src/sys/process/unix/fuchsia.rs
index 3fae5ec1468..ca53a530f46 100644
--- a/library/std/src/sys/process/unix/fuchsia.rs
+++ b/library/std/src/sys/process/unix/fuchsia.rs
@@ -85,7 +85,11 @@ unsafe fn do_exec(
                 zx_cvt(status)?;
 
                 let mut cloned_fd = 0;
-                zx_cvt(fdio_fd_create(handle, &mut cloned_fd))?;
+                let status = fdio_fd_create(handle, &mut cloned_fd);
+                if status < 0 {
+                    zx_handle_close(handle);
+                }
+                zx_cvt(status)?;
 
                 Ok(fdio_spawn_action_t {
                     action: FDIO_SPAWN_ACTION_TRANSFER_FD,
```