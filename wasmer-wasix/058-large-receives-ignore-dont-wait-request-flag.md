# Large receives ignore DONT_WAIT request flag

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/sock_recv_from.rs:86`

## Summary
- `sock_recv_from_internal` derives a per-call `nonblocking_flag` from `__WASI_SOCK_RECV_INPUT_DONT_WAIT`.
- For receive buffers up to `10240`, the syscall passes `fd` nonblocking state OR `nonblocking_flag` into `socket.recv_from(...)`.
- For larger buffers, the branch at `lib/wasix/src/syscalls/wasix/sock_recv_from.rs:86` recomputes `nonblocking` from only `fd.inner.flags.contains(Fdflags::NONBLOCK)`.
- This drops the caller’s `DONT_WAIT` request and can cause a blocking wait for large receives.

## Provenance
- Verified from the provided reproducer and code-path inspection in `lib/wasix/src/syscalls/wasix/sock_recv_from.rs` and `lib/wasix/src/net/socket.rs`
- Scanner provenance: https://swival.dev

## Preconditions
- Caller sets `__WASI_SOCK_RECV_INPUT_DONT_WAIT`
- Total iovec length exceeds `10240`
- Socket itself is not opened with `Fdflags::NONBLOCK`
- No datagram is immediately available to read

## Proof
- `ri_flags` is parsed in `sock_recv_from_internal`, and `nonblocking_flag` is derived from `__WASI_SOCK_RECV_INPUT_DONT_WAIT`.
- In the small-buffer branch, `nonblocking` includes `nonblocking_flag`, preserving the per-call request.
- In the large-buffer branch at `lib/wasix/src/syscalls/wasix/sock_recv_from.rs:86`, `nonblocking` is recalculated from only `fd.inner.flags.contains(Fdflags::NONBLOCK)`.
- `socket.recv_from(...)` consumes only that boolean to decide behavior.
- In `lib/wasix/src/net/socket.rs:1439`, `WouldBlock` maps to immediate `Errno::Again` only when `nonblocking` is true.
- In `lib/wasix/src/net/socket.rs:1442`, the blocking path registers a handler and waits; `lib/wasix/src/net/socket.rs:1463` applies a timeout that can last up to 30 seconds.
- Therefore, a large receive with `DONT_WAIT` can wait and return `Timedout` instead of immediately returning `Again`.

## Why This Is A Real Bug
- `DONT_WAIT` is a per-call nonblocking contract and must not depend on buffer size.
- The implementation already honors that contract for smaller receives, proving the intended behavior.
- The large-buffer branch silently changes syscall semantics based solely on total iovec length.
- This creates observable incorrect behavior: unexpected blocking or timeout instead of immediate `Again`.

## Fix Requirement
- Preserve `nonblocking_flag` in the large-buffer branch when computing the `nonblocking` argument passed to `socket.recv_from(...)`.

## Patch Rationale
- The patch updates the large-buffer branch to compute `nonblocking` consistently with the small-buffer branch.
- This is the minimal change that restores per-call `DONT_WAIT` semantics without altering unrelated receive logic.

## Residual Risk
- None

## Patch
- Patch file: `058-large-receives-ignore-dont-wait-request-flag.patch`
- Change: include `nonblocking_flag` in the large-buffer branch nonblocking calculation in `lib/wasix/src/syscalls/wasix/sock_recv_from.rs`