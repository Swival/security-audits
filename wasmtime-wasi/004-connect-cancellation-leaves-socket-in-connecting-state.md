# Connect cancellation strands TCP socket in connecting state

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `crates/wasi/src/p3/sockets/host/types/tcp.rs:195`
- `crates/wasi/src/sockets/tcp.rs:297`
- `crates/wasi/src/sockets/tcp.rs:364`
- `crates/wasi/src/sockets/tcp.rs:247`
- `crates/wasi/src/p3/sockets/host/types/tcp.rs:507`

## Summary
`connect` transitions the socket into `Connecting(None)` via `start_connect`, then awaits the async OS connect, and only afterward calls `finish_connect`. If the guest cancels the host call during that await, `finish_connect` is skipped and the resource remains stuck in the transitional connecting state. That stranded handle cannot be reused and has no recovery path except destruction.

## Provenance
- Verified finding reproduced from the supplied report and state-machine analysis
- Scanner provenance: https://swival.dev

## Preconditions
- Guest invokes `connect` after `start_connect`
- Guest cancels the async host `connect` call before the await completes

## Proof
- In `crates/wasi/src/p3/sockets/host/types/tcp.rs:195`, `connect` calls `socket.start_connect(&remote_address)?` before awaiting `sock.connect(remote_address).await`.
- The same function only invokes `socket.finish_connect(res)?` after the await returns.
- The implementation includes an inline FIXME noting that cancellation of the outer `connect` is not handled.
- Reproduction shows the resulting `Connecting(None)` state is terminal for the resource:
  - repeated `start_connect` returns `ConcurrencyConflict` at `crates/wasi/src/sockets/tcp.rs:297`
  - `bind` and `listen` reject the state at `crates/wasi/src/sockets/tcp.rs:255` and `crates/wasi/src/sockets/tcp.rs:411`
  - address queries fail at `crates/wasi/src/sockets/tcp.rs:511` and `crates/wasi/src/sockets/tcp.rs:522`
  - helpers using `as_std_view` reject `Connecting(..)` as `InvalidState` at `crates/wasi/src/sockets/tcp.rs:247`
- `finish_connect` is the only p3 transition out of `Connecting(None)` at `crates/wasi/src/sockets/tcp.rs:364`.
- `HostTcpSocket::drop` in `crates/wasi/src/p3/sockets/host/types/tcp.rs:507` only deletes the resource, so the only recovery is dropping and recreating the socket.

## Why This Is A Real Bug
Cancellation is an externally reachable control path for an async host call, not a hypothetical internal fault. On that path, the socket resource is left in a poisoned lifecycle state that rejects further operations and cannot be repaired through the public API. This is a persistent resource loss for the guest and directly violates expected cancellation safety for a connect operation.

## Fix Requirement
Ensure the cancellation path always performs the same state cleanup as the normal completion path, either by guaranteed `finish_connect` execution or by an explicit rollback that restores a valid reusable state before returning.

## Patch Rationale
The patch in `004-connect-cancellation-leaves-socket-in-connecting-state.patch` makes connect cancellation-safe by ensuring the post-`start_connect` transitional state is always resolved, including when the outer async call is dropped before completion. This preserves socket lifecycle invariants and prevents guests from permanently stranding a live socket handle.

## Residual Risk
None

## Patch
- Patch file: `004-connect-cancellation-leaves-socket-in-connecting-state.patch`
- Effect: guarantees canceled `connect` does not leave the resource in `Connecting(None)`
- Result: the socket either completes connection handling or is rolled back to a valid non-poisoned state instead of becoming permanently unusable