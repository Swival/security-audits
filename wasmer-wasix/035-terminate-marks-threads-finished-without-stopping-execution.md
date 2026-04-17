# Terminate marks threads finished before they stop

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/os/task/process.rs:722`
- `lib/wasix/src/os/task/process.rs:766`
- `lib/wasix/src/state/env.rs:858`
- `lib/wasix/src/syscalls/wasix/proc_join.rs:183`

## Summary
`WasiProcess::terminate` marks every registered thread as finished by calling `thread.set_status_finished(Ok(exit_code))` while those threads may still be executing. This lets `join()` and `try_join()` report process completion immediately even though sibling threads can continue running afterward.

## Provenance
- Verified from the provided reproducer and source inspection
- Patch captured in `035-terminate-marks-threads-finished-without-stopping-execution.patch`
- Reference: https://swival.dev

## Preconditions
- The process has one or more registered threads
- At least one non-calling thread is still runnable when process termination begins

## Proof
At `lib/wasix/src/os/task/process.rs:722`, `terminate(exit_code)` acquires `self.inner`, iterates `guard.threads.values()`, and marks each thread finished. The code does not stop, remove, or wait for those threads first, and the nearby FIXME acknowledges they may still be running.

The reproduced behavior shows a sibling thread continuing to execute code after `terminate()` has already marked it finished.

Observers consume this premature finished state:
- `WasiProcess::join()` / `try_join()` read the main thread completion state at `lib/wasix/src/os/task/process.rs:766`
- The main thread shares `self.finished` from `lib/wasix/src/os/task/process.rs:539`
- `WasiEnv::should_exit()` treats `process.try_join()` as exit-complete at `lib/wasix/src/state/env.rs:858`
- `proc_join` returns success from `process.try_join()` at `lib/wasix/src/syscalls/wasix/proc_join.rs:183`

Result: process-level join/exit observers can proceed while registered threads are still executing.

## Why This Is A Real Bug
This violates the basic lifecycle contract implied by termination and join semantics: “finished” should mean execution has ended. Returning successful process completion while sibling threads still run can release resources, trigger teardown, or let callers act on a false assumption that no process code remains active. The reproducer confirms this is not theoretical; it occurs in ordinary multithreaded exit flow, even if some special `terminate()` call sites do not have concurrent siblings.

## Fix Requirement
`terminate()` must first signal or stop each registered thread and only publish finished status after thread exit is confirmed or the thread is removed from the process registry.

## Patch Rationale
The patch in `035-terminate-marks-threads-finished-without-stopping-execution.patch` changes termination ordering so process completion is not reported solely by writing finished state up front. It aligns observable join/exit state with actual thread shutdown, preventing joiners from seeing success before execution has stopped.

## Residual Risk
None

## Patch
- `035-terminate-marks-threads-finished-without-stopping-execution.patch`