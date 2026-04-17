# Scheduler errors panic in async helper

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/task_manager/mod.rs:410`

## Summary
`spawn_await()` called `self.task_dedicated(...)` and immediately `unwrap()`ed the `Result`. If a caller-supplied `VirtualTaskManager` rejects dedicated task submission, the helper panics synchronously instead of returning a recoverable `WasiThreadError`.

## Provenance
- Reproduced from the verified finding and source review
- Public API reachability confirmed through `lib/wasix/src/runtime/task_manager/mod.rs:174`, `lib/wasix/src/runtime/mod.rs:472`, and `lib/wasix/src/runtime/mod.rs:721`
- Scanner reference: https://swival.dev

## Preconditions
- A caller invokes `spawn_await()` with any closure
- The active `VirtualTaskManager` implementation returns `Err(...)` from `task_dedicated()` for that submitted job

## Proof
- `spawn_await()` wraps the caller closure, submits it through `self.task_dedicated(...)`, and previously used `.unwrap()` on the returned `Result` at `lib/wasix/src/runtime/task_manager/mod.rs:410`
- Because `VirtualTaskManager` is a public trait object accepted by runtime constructors, an embedder can provide an implementation whose `task_dedicated()` returns `Err(WasiThreadError::Unsupported)`
- In that configuration, calling `spawn_await(...)` panics before any future is returned, replacing normal error propagation with process or thread termination
- The issue is directly reachable for custom embedders even though in-tree managers may not currently trigger it

## Why This Is A Real Bug
This helper advertises fallible task execution semantics via `WasiThreadError`, but the internal `unwrap()` converts a scheduler failure into an unconditional panic. That is a behavioral regression from recoverable API error handling to abort-like failure, and it is externally triggerable by supported embedders supplying a rejecting scheduler.

## Fix Requirement
Change `spawn_await()` to propagate `task_dedicated()` failures as `Err(WasiThreadError)` instead of panicking.

## Patch Rationale
The patch removes the `unwrap()` path and returns the scheduling failure through the helper's existing result channel. This preserves the public API contract, keeps failure handling explicit, and prevents synchronous panics when dedicated-task submission is unsupported or otherwise rejected.

## Residual Risk
None

## Patch
- Patch file: `050-scheduler-errors-panic-in-async-helper.patch`
- The patch updates `lib/wasix/src/runtime/task_manager/mod.rs` so `spawn_await()` returns scheduler submission errors instead of unwrapping them and panicking