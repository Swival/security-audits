# Duplicate shard spin-up race fixed

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runners/dproxy/factory.rs:34`
- `lib/wasix/src/runners/dproxy/factory.rs:50`
- `lib/wasix/src/runners/dproxy/factory.rs:102`
- `lib/wasix/src/runners/dproxy/factory.rs:112`

## Summary
Concurrent `acquire()` calls for the same shard could both observe the cache empty, both start `spin_up()`, and then race to overwrite the single cached entry. This broke the intended one-runner-per-shard behavior and allowed an older background task to later remove a newer cached instance.

## Provenance
- Verified from the provided reproducer and patch context
- Source file: `lib/wasix/src/runners/dproxy/factory.rs`
- Scanner reference: https://swival.dev

## Preconditions
- Two `acquire()` calls target the same shard
- Both calls overlap before cache insertion completes
- At least one spawned shard task remains alive long enough for the second insert or later cleanup to occur

## Proof
- `acquire()` checked `state.instance` while holding the mutex, then dropped the lock before awaiting `spin_up(handler, shard.clone())` at `lib/wasix/src/runners/dproxy/factory.rs:34`.
- During that await window, a second caller for the same shard could also see no cached instance and call `spin_up()` for the same shard.
- The Tokio task manager executes the spawned dedicated task immediately, so both shard processes actually start at `lib/wasix/src/runners/dproxy/factory.rs:102` and `lib/wasix/src/runtime/task_manager/tokio.rs:319`.
- Only one cache slot exists per shard, so the later `HashMap::insert()` overwrote the earlier instance at `lib/wasix/src/runners/dproxy/factory.rs:50`.
- The background task cleanup then unconditionally removed the shard entry at `lib/wasix/src/runners/dproxy/factory.rs:112`, so an older overwritten instance could delete the newer authoritative cache entry after exit.

## Why This Is A Real Bug
The race is reachable under normal concurrent use of `acquire()`. It causes duplicate instance creation, violates shard affinity/state reuse, wastes resources, and can trigger repeated cold starts when stale instance shutdown removes the current cache entry. This is observable behavior, not a theoretical locking concern.

## Fix Requirement
Reserve shard startup while holding the mutex, and make concurrent callers await the same in-flight initialization instead of independently calling `spin_up()`. Cleanup must only remove the cache entry owned by the exiting instance.

## Patch Rationale
The patch introduces shared in-flight startup state for each shard so only one `spin_up()` executes per shard at a time. Other concurrent callers join that startup and reuse its result. It also ties cleanup to the specific cached instance so an older overwritten runner cannot remove a newer shard entry.

## Residual Risk
None

## Patch
- Patch file: `015-duplicate-spin-up-races-for-same-shard.patch`
- Fixes the race in `lib/wasix/src/runners/dproxy/factory.rs`
- Ensures one in-flight spin-up per shard
- Prevents stale runner shutdown from removing a newer cached instance