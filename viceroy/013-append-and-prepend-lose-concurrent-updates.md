# Append and prepend lose concurrent updates

## Classification
- Type: race condition
- Severity: high
- Confidence: certain

## Affected Locations
- `src/object_store.rs:99`
- `src/object_store.rs:119`
- `src/object_store.rs:132`
- `src/object_store.rs:170`
- `src/object_store.rs:955`

## Summary
`append` and `prepend` perform a read-modify-write using a stale snapshot. `insert` first reads the current object, releases that lock, rebuilds a new body from the earlier value, and only later reacquires the store write lock to publish it. Concurrent writers targeting the same key can therefore overwrite each other, dropping one update.

## Provenance
- Verified from the provided finding and reproducer details.
- Independent reproduction was recorded with a focused concurrent test in `src/object_store.rs:955`.
- Scanner reference: https://swival.dev

## Preconditions
- Two inserts target the same key concurrently using `append` or `prepend`.

## Proof
- `insert` obtains the prior value via `lookup`, which clones the object under a separate lock before the final write path at `src/object_store.rs:170`.
- In `Append`, the replacement body is built from that earlier snapshot at `src/object_store.rs:119`.
- In `Prepend`, the replacement body is likewise rebuilt from the stale snapshot at `src/object_store.rs:132`.
- No compare-and-swap, generation recheck, or retry occurs between the snapshot-based recomputation and `store.insert` at `src/object_store.rs:170`.
- The concurrent regression test at `src/object_store.rs:955` repeatedly races two appenders on one key and passes only when one payload is lost, demonstrating the bug in practice.

## Why This Is A Real Bug
Both writers can legally observe the same initial body, derive different full replacements, and then serialize their final `store.insert` operations. The second insert wins and erases the first writer's appended or prepended bytes. This is externally observable data loss on a normal concurrent API path, not a theoretical synchronization concern.

## Fix Requirement
The update must become atomic for a given key. Hold a single write lock across the read-modify-write sequence, or implement a compare-and-swap style retry that revalidates the object generation before committing the rebuilt body.

## Patch Rationale
The patch in `013-append-and-prepend-lose-concurrent-updates.patch` removes the stale-snapshot write pattern by making append/prepend updates commit against current state under one synchronization boundary. That directly prevents an intervening writer from being overwritten by an older recomputation.

## Residual Risk
None

## Patch
- Patch file: `013-append-and-prepend-lose-concurrent-updates.patch`
- The patch aligns with the required fix by eliminating the unlocked gap between reading the existing value and writing the rebuilt appended/prepended value.