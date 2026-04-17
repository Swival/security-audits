# Restore uses prior region end when sizing decompressed memory

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/journal/effector/memory_and_snapshot.rs:189`
- `lib/wasix/src/journal/effector/memory_and_snapshot.rs:222`

## Summary
During restore, compressed memory updates are decompressed and then applied at `region.start`, but the growth check uses `region.end + uncompressed_size` instead of the actual write end. For any valid saved region with a nonzero start offset, this can grow linear memory beyond the snapshot’s real restored contents, breaking snapshot size fidelity.

## Provenance
- Verified from the supplied reproducer and patched at the reported location
- Source context reviewed in `lib/wasix/src/journal/effector/memory_and_snapshot.rs`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Restoring a compressed memory region whose saved `region.start` is nonzero

## Proof
`UpdateMemoryRegionV1.region` is snapshot metadata and is passed into `apply_compressed_memory`. The routine derives the decompressed length from `compressed_data`, then computes the required memory size from the wrong base offset.

Observed behavior:
- restore grows memory using `region.end + uncompressed_size`
- restore writes decompressed bytes starting at `region.start`
- therefore the true required bound is `region.start + uncompressed_size`

Concrete reproduced case:
- saved region `4096..4608`
- decompressed length `512`
- restore grows memory to `5120`
- write covers only `4096..4608`

This leaves extra restored address space visible after replay. No shrink occurs in this path, so restored linear memory length can exceed the snapshotted size.

## Why This Is A Real Bug
This is reachable with legitimate snapshot metadata; no malformed input is required. Any compressed restore chunk starting at a nonzero offset triggers sizing from the wrong base. The resulting memory length is externally observable through normal Wasm memory bounds behavior such as `memory.size`, and subsequent journaling can persist the inflated state.

## Fix Requirement
Grow memory to the actual decompressed write end after checked arithmetic:
- `region.start + uncompressed_size as u64`

## Patch Rationale
The patch changes the growth target to the computed write end derived from `region.start` and the decompressed byte length, preserving snapshot fidelity and aligning allocation with the bytes actually restored.

## Residual Risk
None

## Patch
- Patch file: `044-restore-grows-memory-using-wrong-base-offset.patch`
- Patched file: `lib/wasix/src/journal/effector/memory_and_snapshot.rs`
- Change: replace growth sizing based on `region.end + uncompressed_size` with sizing based on the checked decompressed write end from `region.start`