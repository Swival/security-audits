# Non-child `proc_join` bypasses parent-child restriction

## Classification
- Type: authorization flaw
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/proc_join.rs:149`
- `lib/wasix/src/os/task/process.rs:766`
- `lib/wasix/src/os/task/process.rs:772`

## Summary
`proc_join` accepts an arbitrary PID from `pid_ptr` and is expected to restrict joins to the caller's child processes. Instead, when no matching child is found, `proc_join_internal` falls back to `control_plane.get_process(pid)` and joins any existing process returned there. This allows a caller to observe or await unrelated processes and obtain their exit status.

## Provenance
- Verified from the supplied finding and reproducer
- Reproduced against the referenced code paths
- Swival Security Scanner: https://swival.dev

## Preconditions
- Caller can invoke `proc_join` with a PID not present in its `children` set

## Proof
- `proc_join` reads `pid_ptr` and converts `Some(pid)` into a `WasiProcessId`, entering the normal targeted-join path in `lib/wasix/src/syscalls/wasix/proc_join.rs:101`.
- `proc_join_internal` searches `children` for the requested PID and removes only a matching child entry in `lib/wasix/src/syscalls/wasix/proc_join.rs:149`.
- If no child matches, the code falls back to `ctx.data().control_plane.get_process(pid)` instead of rejecting the request in `lib/wasix/src/syscalls/wasix/proc_join.rs:174`.
- `try_join()` and `join()` perform no parent-child authorization checks in `lib/wasix/src/os/task/process.rs:766` and `lib/wasix/src/os/task/process.rs:772`.
- As reproduced, an existing unrelated PID can therefore be polled with `NON_BLOCKING` or awaited until exit, and its PID and exit status are written back through `pid_ptr`/`exit_code_ptr`. A nonexistent non-child PID returns `JoinStatus::Nothing` rather than `Errno::Child` in `lib/wasix/src/syscalls/wasix/proc_join.rs:202`.

## Why This Is A Real Bug
The syscall's intended authorization boundary is the caller's child-process set. The fallback lookup crosses that boundary and converts `proc_join` into a general process-observation primitive for any existing PID reachable through the control plane. This leaks process existence and termination state and permits retrieval of unrelated exit codes, which is a direct authorization failure.

## Fix Requirement
Remove the non-child fallback and reject targeted joins for PIDs outside the caller's `children` set with `Errno::Child`.

## Patch Rationale
The patch in `055-non-child-process-join-bypasses-parent-child-restriction.patch` enforces the child-only invariant at the syscall boundary by deleting the `control_plane.get_process(pid)` fallback and returning `Errno::Child` when no matching child is found. That restores the intended authorization model without changing valid child-join behavior.

## Residual Risk
None

## Patch
- `055-non-child-process-join-bypasses-parent-child-restriction.patch` removes the unrelated-process lookup path from `lib/wasix/src/syscalls/wasix/proc_join.rs`
- Targeted `proc_join` now fails with `Errno::Child` when the requested PID is not one of the caller's children
- Valid joins for actual child processes continue through the existing `try_join()` / `join()` flow unchanged