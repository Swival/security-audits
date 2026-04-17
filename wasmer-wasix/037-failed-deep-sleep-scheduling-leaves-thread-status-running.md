# Deep-sleep reschedule failure skips process teardown

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/bin_factory/exec.rs:282`

## Summary
When deep-sleep recovery attempts to reschedule execution and `resume_wasm_after_poller(...)` returns `Err`, the main-thread path logs the failure and returns immediately. That bypasses normal exit cleanup, including `blocking_on_exit` and recycle handling, so process teardown remains incomplete.

## Provenance
- Verified from the supplied reproducer and source inspection
- Scanner provenance: `https://swival.dev`

## Preconditions
- `resume_wasm_after_poller` returns `Err` during handling of guest-triggered `WasiError::DeepSleep`
- Execution is on the `spawn_exec` main-thread cleanup path

## Proof
- `call_module` can surface guest-controlled `WasiError::DeepSleep`, which enters the deep-sleep recovery branch in `lib/wasix/src/bin_factory/exec.rs:282`.
- That branch constructs `respawn` and calls `tasks.resume_wasm_after_poller(...)`.
- `resume_wasm_after_poller(...)` can fail by propagating task setup errors from `task_wasm(...)`, including fresh memory-sharing or instantiation failures.
- On that failure, the code logs `failed to go into deep sleep` and returns immediately.
- The thread status is still finalized by `ThreadRunGuard` drop logic in `lib/wasix/src/os/task/thread.rs:204`, so the originally reported “thread left running” effect does not hold.
- However, unlike other exit paths, this early return skips `blocking_on_exit` and recycle handling, leaving process teardown incomplete. This behavior was reproduced.

## Why This Is A Real Bug
The failure path is reachable from a real propagated scheduler/setup error and exits without the same teardown performed by adjacent terminal paths. That creates inconsistent lifecycle handling for the process: the thread is marked finished, but environment exit and recycling work are skipped. This can leave execution state partially torn down after a failed deep-sleep reschedule.

## Fix Requirement
Ensure the `resume_wasm_after_poller(...)` error branch performs the same main-thread exit cleanup as other terminal paths before returning, including normal blocking-exit and recycle/finalization behavior.

## Patch Rationale
The patch updates the deep-sleep scheduling failure branch in `lib/wasix/src/bin_factory/exec.rs` to run the standard teardown sequence before returning. This preserves the existing error handling intent while aligning lifecycle cleanup with the other early-exit paths and preventing incomplete process shutdown.

## Residual Risk
None

## Patch
- Patch file: `037-failed-deep-sleep-scheduling-leaves-thread-status-running.patch`
- Patch scope: `lib/wasix/src/bin_factory/exec.rs`
- Patch effect: on deep-sleep reschedule failure, execute normal exit cleanup before returning instead of only logging and exiting early.