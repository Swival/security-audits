# Insert preconditions race concurrent writers

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `src/object_store.rs:78`

## Summary
`insert` validated `KvInsertMode::Add` and `if_generation_match` against a snapshot read under a separate lock, then released that lock before taking the write lock that performs `store.insert`. Concurrent writers targeting the same key could both pass stale precondition checks and commit, breaking add-only exclusivity and generation-match guarantees.

## Provenance
- Verified finding reproduced from scanner report
- Scanner source: https://swival.dev
- Reproducer confirmed two concurrent `Add` inserts on the same empty key both returned `Ok`
- Reproducer also confirmed stale generation validation during concurrent append-style updates, resulting in successful responses with a lost update

## Preconditions
- Two inserts target the same key concurrently

## Proof
- `insert` accepted caller-controlled `mode` and `if_generation_match`
- The prior implementation read current state via `lookup`, evaluated preconditions from that stale `existing` value, then later acquired a write lock and updated the map
- Because the read-side state was not revalidated inside the write-side critical section, an intervening writer could change the same key after validation but before commit
- Reproduction showed both concurrent `KvInsertMode::Add` operations succeeded on the same initially empty key
- Reproduction also showed two concurrent writes using the same starting generation both succeeded, while the final stored body reflected only one update

## Why This Is A Real Bug
The API promises conditional write semantics: `Add` should fail if the key already exists, and `if_generation_match` should fail if the object generation changed. Those guarantees require an atomic check-and-write sequence over the same key. The old implementation split validation and mutation across separate lock acquisitions, so success responses could be returned for writes that should have been rejected. This is externally observable and causes correctness failures, including lost updates.

## Fix Requirement
Perform precondition validation and mutation while holding a single write lock on the store, and re-read the current value from the protected map inside that critical section before applying the update.

## Patch Rationale
The patch moves the precondition check into the write-locked section of `insert`, using the current in-lock object state as the source of truth for both mode validation and generation validation before computing and storing the new value. This restores atomicity for the check-and-update path and prevents concurrent writers from committing based on stale state.

## Residual Risk
None

## Patch
- Patch file: `012-insert-preconditions-race-concurrent-writers.patch`
- The patch updates `src/object_store.rs` so `insert` no longer relies on a pre-lock snapshot for correctness-critical validation
- The write path now rechecks current object presence and generation while the write lock is held, then applies the insert/update in the same critical section