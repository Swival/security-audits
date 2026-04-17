# Task manager thread pool is oversized by default

## Classification
- Severity: medium
- Type: resource lifecycle bug
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/task_manager/tokio.rs:71`
- `lib/wasix/src/syscalls/wasix/thread_spawn.rs:181`
- `lib/wasix/src/capabilities.rs:72`
- `lib/wasix/src/state/builder.rs:1059`

## Summary
`TokioTaskManager::new` configures the dedicated task pool with `core_size` and `max_size` set to `200usize.max(concurrency * 100)`. Reachable submission paths, including WASIX thread creation, enqueue work onto that pool. Under the default configuration, there is no lower built-in task cap, so repeated submissions can grow the pool to hundreds of resident host threads per runtime instance.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner: https://swival.dev

## Preconditions
- `TokioTaskManager` is constructed
- Many dedicated or WASIX thread tasks are submitted
- Default or otherwise permissive task-count controls allow repeated submissions

## Proof
`TokioTaskManager::new` in `lib/wasix/src/runtime/task_manager/tokio.rs:71` computes `max_threads = 200usize.max(concurrency * 100)` and passes that value to `rusty_pool::Builder` as both `core_size` and `max_size`.

Work reaches this pool through `self.pool.execute(...)` on dedicated execution paths, including the non-trigger `task_wasm` path. One reachable creation path is `thread_spawn_internal_using_layout()` in `lib/wasix/src/syscalls/wasix/thread_spawn.rs:181`, which calls `tasks.task_wasm(...)`.

The built-in control-plane task cap does not prevent this by default: `max_task_count` defaults to `None` in `lib/wasix/src/capabilities.rs:72`, and that value is propagated into runtime control-plane configuration in `lib/wasix/src/state/builder.rs:1059`.

Reproduction confirmed that the pool does not immediately create 200 workers at construction, but repeated submissions can drive it up to that configured size, after which those threads remain resident until `TokioTaskManager` is dropped.

## Why This Is A Real Bug
This is a practical host resource-consumption flaw. A caller able to submit many dedicated or WASIX thread tasks can force a single runtime instance to retain hundreds of OS threads. That increases memory footprint, scheduler contention, and cross-tenant interference risk, and can exhaust thread limits on constrained hosts.

## Fix Requirement
Bound the dedicated pool to a small maximum by default, and preferably make the limit configurable from caller or runtime configuration context instead of deriving it as `max(200, concurrency * 100)`.

## Patch Rationale
The patch reduces the dedicated pool sizing from the unboundedly large default formula to a small bounded limit, preventing routine task submission from scaling a runtime instance to hundreds of resident host threads. This preserves dedicated execution behavior while removing the excessive default resource reservation ceiling.

## Residual Risk
None

## Patch
- Patch file: `027-task-manager-can-allocate-hundreds-of-dedicated-threads.patch`