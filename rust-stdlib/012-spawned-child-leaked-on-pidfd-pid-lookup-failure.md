# Spawned Child Leaked On pidfd PID Lookup Failure

## Classification

Resource lifecycle bug. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/process/unix/unix.rs:790`

## Summary

On Linux, the `pidfd_spawnp` fast path can successfully create a child process and return a pidfd, then fail while resolving the child PID from that pidfd. The error branch returned immediately without establishing `Process` ownership, killing the child, or waiting for it. This made the caller observe spawn failure while the child remained alive or later became an unreaped zombie.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Target is Linux.
- `Command` uses pidfd creation.
- `PIDFD_SUPPORTED == SPAWN`.
- `pidfd_spawnp` succeeds and creates the child.
- `pidfd.pid()` returns an error after the child has been spawned.

## Proof

In the pidfd `posix_spawn` path, `pidfd_spawnp` is called and `spawn_res?` confirms success. The returned raw fd is wrapped as `PidFd`, then `pidfd.pid()` is called.

Before the patch, the `Err(e)` arm immediately returned:

```rust
return Err(Error::new(
    e.kind(),
    "pidfd_spawnp succeeded but the child's PID could not be obtained",
));
```

The nearby comment explicitly states that the child has already been spawned and the pidfd is held. No `Process::new`, `Process::wait`, `Process::kill`, `PidFd::wait`, or `PidFd::send_signal` equivalent was invoked before returning the error.

A practical trigger is exhausting the fd table after pidfd support probing succeeds, so `pidfd_spawnp` can create the child and consume the remaining fd slot, while the subsequent PID lookup fails through its fallback path. The caller receives an error even though an exec'd child exists.

## Why This Is A Real Bug

The code acknowledges that the child has been spawned, but returns an error before transferring ownership to a `Process`. That violates the process lifecycle invariant: once a child exists, either a handle must be returned to the caller or the implementation must clean it up. Without cleanup, a still-running child becomes unowned from the caller's perspective; if it exits, it can remain a zombie until an unrelated wait or parent termination.

## Fix Requirement

On `pidfd.pid()` failure after successful `pidfd_spawnp`, the implementation must clean up the already-spawned child before returning an error. Cleanup must use the held pidfd so it does not depend on knowing the numeric PID.

## Patch Rationale

The patch adds cleanup in the `pidfd.pid()` error branch:

```rust
let _ = pidfd.kill();
let _ = pidfd.wait();
```

This uses the pidfd already obtained from `pidfd_spawnp` to target the correct child without PID lookup. `kill()` requests termination, and `wait()` reaps the child. Errors are intentionally ignored because the function is already returning the original PID lookup failure; cleanup is best-effort but directly addresses the leak path.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/unix/unix.rs b/library/std/src/sys/process/unix/unix.rs
index a68be2543bc..bfaaab16588 100644
--- a/library/std/src/sys/process/unix/unix.rs
+++ b/library/std/src/sys/process/unix/unix.rs
@@ -800,6 +800,8 @@ fn drop(&mut self) {
                         // was verified earlier.
                         // This is quite unlikely, but might happen if the ioctl is not supported,
                         // glibc tries to use procfs and we're out of file descriptors.
+                        let _ = pidfd.kill();
+                        let _ = pidfd.wait();
                         return Err(Error::new(
                             e.kind(),
                             "pidfd_spawnp succeeded but the child's PID could not be obtained",
```