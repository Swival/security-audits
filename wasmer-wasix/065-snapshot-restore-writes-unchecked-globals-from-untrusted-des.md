# Snapshot restore accepts malformed global counts and crashes on restore

## Classification
Validation gap, medium severity, confidence: certain

## Affected Locations
- `lib/wasix/src/utils/store.rs:28`

## Summary
`StoreSnapshot::deserialize()` accepts attacker-controlled snapshot bytes and `restore_store_snapshot()` restores every deserialized global without first validating that the snapshot global count matches the target store global count. An oversized `snapshot.globals` vector does not achieve an unchecked memory write in practice, because lower layers assert on out-of-range indices, but it does reliably turn malformed input into a restore-time panic / failure.

## Provenance
Reported from verified finding reproduction and patch validation. External scanner reference: https://swival.dev

## Preconditions
- Attacker controls snapshot bytes passed to `StoreSnapshot::deserialize()`
- The deserialized snapshot is later restored through the snapshot rewind / restore path

## Proof
`StoreSnapshot::deserialize()` decodes untrusted bytes into `StoreSnapshot.globals`, and `restore_store_snapshot()` iterates `snapshot.globals` and calls `objs.set_global_unchecked(index, *value)` for each entry in `lib/wasix/src/utils/store.rs:28`.

Reproduction confirmed that backend/store implementations enforce `idx < self.globals.len()` with assertions, including:
- `lib/vm/src/store.rs:134`
- `lib/api/src/entities/store/obj.rs:97`
- `lib/api/src/backend/js/entities/store/obj.rs:98`
- `lib/api/src/backend/jsc/entities/store/obj.rs:98`
- `lib/api/src/backend/v8/entities/store/obj.rs:125`
- `lib/api/src/backend/wamr/entities/store/obj.rs:125`
- `lib/api/src/backend/wasmi/entities/store/obj.rs:125`

As a result, when a deserialized snapshot contains more globals than the store actually owns, restoration reaches the first invalid index and asserts, causing a panic / restore failure. The restore path therefore trusts malformed length metadata until it crashes.

## Why This Is A Real Bug
This is externally reachable from untrusted serialized snapshot input and causes deterministic denial of service in the restore path. The original impact was overstated as unchecked out-of-bounds memory write, but the missing pre-validation is still a correctness and availability bug: malformed snapshots are not rejected cleanly at the trust boundary and instead fail deep inside restore logic.

## Fix Requirement
Before restoring globals, validate that `snapshot.globals.len()` exactly matches the target store's global count and reject mismatches with an error instead of entering the unchecked restore loop.

## Patch Rationale
The patch in `065-snapshot-restore-writes-unchecked-globals-from-untrusted-des.patch` adds an explicit global-count consistency check in the restore path, converting malformed snapshots from assertion-triggering input into a normal validation failure. This enforces restore invariants at the boundary where untrusted deserialized state is consumed.

## Residual Risk
None

## Patch
The patch updates `lib/wasix/src/utils/store.rs` to verify the deserialized global vector length against the destination store before any writes occur. If the counts differ, restoration returns an error and does not call `set_global_unchecked()` for invalid indices.