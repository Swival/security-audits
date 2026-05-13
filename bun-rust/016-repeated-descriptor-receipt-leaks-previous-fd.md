# Repeated Descriptor Receipt Leaks Previous FD

## Classification

Denial of service, medium severity.

## Affected Locations

`src/jsc/ipc.rs:2110`

## Summary

`IPCHandlers::PosixSocket::on_fd` accepted peer-supplied POSIX `SCM_RIGHTS` descriptors and stored them in `send_queue.incoming_fd`. When a descriptor was already pending, the code logged that it was overwriting the value but did not close the previous descriptor. Because `Fd` is a copyable integer wrapper without automatic close-on-drop behavior, repeated descriptor receipt before a matching `NODE_HANDLE` message leaked one receiver-side fd per overwrite.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- POSIX IPC socket accepts `SCM_RIGHTS` descriptors from a peer.
- A malicious local IPC peer can send multiple descriptors before any corresponding `NODE_HANDLE` message consumes `incoming_fd`.

## Proof

The reproduced path is:

- `src/runtime/socket/uws_handlers.rs:807` routes received POSIX descriptors into `IPCHandlers::PosixSocket::on_fd`.
- `src/jsc/ipc.rs:2107` logs the received fd.
- The vulnerable code checked `send_queue.incoming_fd.is_some()`, logged `"incoming_fd already set; overwriting"`, then assigned `send_queue.incoming_fd = Some(Fd::from_native(fd))`.
- `Fd` is a `Copy` integer wrapper with no `Drop` in `src/bun_core/util.rs:932`, so overwriting `Option<Fd>` does not close the old descriptor.
- `SendQueue::drop` closes only the final stored `incoming_fd` at `src/jsc/ipc.rs:1737`; descriptors overwritten earlier are no longer reachable.

A malicious peer can repeatedly send valid `SCM_RIGHTS` descriptors with non-`NODE_HANDLE` IPC data, or send multiple descriptors before any `NODE_HANDLE`, causing one fd leak per overwrite until process fd exhaustion.

## Why This Is A Real Bug

The overwritten fd remains open in the receiving process but is no longer referenced by `SendQueue`. No later cleanup path can close it because only the current `incoming_fd` is retained. Since fd tables are finite per process, an attacker-controlled local IPC peer can repeatedly trigger the leak and force fd exhaustion, producing denial of service.

## Fix Requirement

Before replacing `send_queue.incoming_fd`, the implementation must either:

- close the already pending descriptor, or
- reject and close the newly received extra descriptor.

The patched behavior closes the existing pending descriptor before storing the replacement.

## Patch Rationale

The patch changes the overwrite branch from a read-only `is_some()` check to `take()`. This removes the existing fd from `incoming_fd`, closes it with `FdExt::close(existing_fd)`, then stores the newly received descriptor. This preserves existing replacement semantics while ensuring no previously pending fd becomes unreachable.

## Residual Risk

None

## Patch

```diff
diff --git a/src/jsc/ipc.rs b/src/jsc/ipc.rs
index 6b7fa34e13..b6a7130a4a 100644
--- a/src/jsc/ipc.rs
+++ b/src/jsc/ipc.rs
@@ -2107,8 +2107,9 @@ pub mod IPCHandlers {
             #[cfg(not(windows))]
             {
                 log!("onFd: {}", fd);
-                if send_queue.incoming_fd.is_some() {
+                if let Some(existing_fd) = send_queue.incoming_fd.take() {
                     log!("onFd: incoming_fd already set; overwriting");
+                    FdExt::close(existing_fd);
                 }
                 send_queue.incoming_fd = Some(Fd::from_native(fd));
             }
```