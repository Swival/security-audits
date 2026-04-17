# Non-self `proc_parent` returns target PID

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/proc_parent.rs:18`
- `lib/wasix/src/syscalls/wasix/proc_parent.rs:19`

## Summary
For non-self `proc_parent` calls, the syscall looks up the target process and writes `process.pid()` to the caller’s output buffer instead of the target process’s parent PID. When the queried PID belongs to another live process, the syscall returns the target PID, violating the documented parent-handle contract and corrupting the result.

## Provenance
- Verified from the provided reproducer and code inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- The `proc_parent` syscall is invoked with a PID different from the caller’s PID
- That PID resolves to an existing live process via the control plane

## Proof
At `lib/wasix/src/syscalls/wasix/proc_parent.rs:18`, the non-self branch obtains a `process` via `env.control_plane.get_process(pid)`. It then traces and stores `process.pid().raw()` at `lib/wasix/src/syscalls/wasix/proc_parent.rs:18` and writes the same value to `ret_parent` at `lib/wasix/src/syscalls/wasix/proc_parent.rs:19`. This value is the queried process ID, not its parent. The syscall contract is to return the parent handle, so any successful cross-process lookup yields an incorrect result.

## Why This Is A Real Bug
The bad value is not theoretical: the syscall argument is attacker-controlled within API constraints, and `get_process` performs a global lookup of live processes. If the caller supplies another valid PID, execution reaches the non-self branch and deterministically returns the wrong field. This is observable guest-facing corruption of syscall output and breaks any consumer relying on accurate parent-process identity.

## Fix Requirement
Replace use of `process.pid()` in the non-self branch with `process.ppid()` for both tracing and the value written to `ret_parent`.

## Patch Rationale
The patch updates the non-self branch in `lib/wasix/src/syscalls/wasix/proc_parent.rs` to read the queried process’s parent PID instead of echoing the queried PID. This aligns behavior with the syscall contract and with the self-query path’s parent-oriented semantics.

## Residual Risk
None

## Patch
Patched in `070-non-self-path-returns-target-pid-instead-of-parent-pid.patch`.