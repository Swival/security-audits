# Child registration survives fork spawn failure

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/proc_fork.rs:73`
- `lib/wasix/src/syscalls/wasix/proc_join.rs:154`
- `lib/wasix/src/syscalls/wasix/proc_join.rs:183`
- `lib/wasix/src/os/task/process.rs:793`
- `lib/wasix/src/os/task/process.rs:819`
- `lib/wasix/src/os/task/thread.rs:595`

## Summary
`proc_fork` registers the child PID in the parent's `children` list before attempting `task_wasm` spawn. If spawn then fails, the error is logged and discarded, and `proc_fork` still returns success with the new PID. The scheduled child never exists, but the parent retains a stale child registration that downstream join/cleanup paths treat as a legitimate exited child.

## Provenance
- Verified by local reproduction against the cited code paths
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `fork()` succeeds far enough to allocate/register the child process
- `tasks_outer.task_wasm(...)` returns `Err` afterward

## Proof
`proc_fork` pushes `child_env.process` into `inner.children` before spawn is attempted at `lib/wasix/src/syscalls/wasix/proc_fork.rs:73`. The later `task_wasm(...).map_err(...).ok()` path suppresses spawn failure and still returns `ForkResult { pid: child_pid, ret: Success }`.

Reproduction confirmed the stale-registration effect:
- the child thread object itself is cleaned up when the unscheduled closure is dropped, via `WasiThreadHandle` destruction at `lib/wasix/src/os/task/thread.rs:595`
- but the parent-side `children` entry remains
- `proc_join` then accepts that PID as a joinable child and can return normal success from `lib/wasix/src/syscalls/wasix/proc_join.rs:154` and `lib/wasix/src/syscalls/wasix/proc_join.rs:183`
- absent an explicit join, cleanup does not remove the stale child from the parent list because removal occurs in join-driven paths at `lib/wasix/src/os/task/process.rs:793` and `lib/wasix/src/os/task/process.rs:819`

## Why This Is A Real Bug
This is a real state-consistency failure, not a logging-only issue. After spawn failure, callers observe a successful fork and a child PID that was never actually spawned. That violates fork semantics, creates a persistent stale child entry, and allows `proc_join` to report success for a nonexistent child. The inconsistency is externally observable and can alter process-control behavior.

## Fix Requirement
On `task_wasm` failure, `proc_fork` must not leave the child registered as a live/joinable child while still reporting success. Acceptable fixes are:
- register the child only after successful spawn, or
- roll back parent/child registration and return an error if spawn fails

## Patch Rationale
The patch removes the false-success path by coupling child registration with successful spawn completion. This preserves parent/child state invariants: a PID is only exposed as a child if a child task was actually launched. It also prevents `proc_join` from consuming stale child entries created solely by failed spawn attempts.

## Residual Risk
None

## Patch
- `012-child-remains-registered-after-spawn-failure.patch` updates `proc_fork` to stop reporting success for a child that failed to spawn
- the change ensures parent child-tracking is not left in a stale state after `task_wasm` error
- this aligns `proc_fork` return value with actual runtime state and removes the reproduced join inconsistency