# Task limit check admits one extra task

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/os/task/control_plane.rs:100`
- `lib/wasix/src/os/task/process.rs:531`
- `lib/wasix/src/syscalls/wasix/thread_spawn.rs:95`
- `lib/wasix/src/os/task/thread.rs:250`
- `lib/wasix/src/os/task/thread.rs:276`
- `lib/wasix/src/os/task/control_plane.rs:135`

## Summary
`register_task()` increments `task_count` with `fetch_add(1)` and checks `count > max` instead of `count >= max`. Because `fetch_add` returns the pre-increment value, task creation succeeds when the current count already equals `max_task_count`, leaving `task_count == max + 1` and admitting one extra live task beyond the configured cap.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- `max_task_count` is configured
- Task creation reaches the configured task limit
- Execution reaches the thread creation path that calls `register_task()`

## Proof
- `thread_spawn` reaches process thread creation at `lib/wasix/src/syscalls/wasix/thread_spawn.rs:95`.
- That path calls `register_task()` from `lib/wasix/src/os/task/process.rs:531`.
- `register_task()` performs `fetch_add(1)` and evaluates the returned prior count at `lib/wasix/src/os/task/control_plane.rs:100`.
- With `task_count == max_task_count`, `fetch_add(1)` returns `max_task_count`, the `count > max` check does not fire, and registration succeeds with the stored counter now equal to `max_task_count + 1`.
- The resulting `TaskCountGuard` is retained in live thread state at `lib/wasix/src/os/task/thread.rs:250` and `lib/wasix/src/os/task/thread.rs:276`, so the excess task remains concurrently admitted until thread teardown.
- `new_process()` uses the stricter `>= max` comparison at `lib/wasix/src/os/task/control_plane.rs:135`, confirming `register_task()` is the inconsistent off-by-one case.

## Why This Is A Real Bug
The configured maximum task count is a hard concurrency invariant. Once the system is already at the configured limit, admitting one additional task violates that invariant in a reachable syscall path and leaves the extra task active, not merely overcounted transiently. This can undermine resource isolation and any policy that depends on the limit being exact.

## Fix Requirement
Change the limit check in `register_task()` to reject when the pre-increment count is `>= max_task_count`, and roll back the increment before returning the error.

## Patch Rationale
The patch aligns `register_task()` with the intended limit semantics and with the existing `new_process()` boundary check. Rolling back the increment preserves counter correctness on rejection and prevents persistent over-admission of concurrent tasks.

## Residual Risk
None

## Patch
`045-task-limit-check-admits-one-extra-task.patch` updates `lib/wasix/src/os/task/control_plane.rs` so `register_task()` rejects when the prior count is `>= max_task_count` and decrements the counter on the failure path, preventing `task_count` from remaining above the configured maximum.