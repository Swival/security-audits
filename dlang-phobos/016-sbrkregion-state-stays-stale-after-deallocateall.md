# SbrkRegion stale state after `deallocateAll`

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/region.d:758`
- `std/experimental/allocator/building_blocks/region.d:1074`

## Summary
`SbrkRegion.deallocateAll()` resets the process break with `brk(_brkInitial)` but does not update the allocator's internal `_brkCurrent` cursor on success. This leaves allocator state inconsistent with the real program break. Subsequent `empty()` and last-block `deallocate()` decisions use stale state and can report incorrect emptiness or attempt an extra shrink based on obsolete allocation history.

## Provenance
- Verified from repository source and reproduced from the public API path described in the finding
- Scanner source: https://swival.dev

## Preconditions
- Posix `SbrkRegion` is initialized
- `brk(_brkInitial)` succeeds inside `deallocateAll()`

## Proof
- In `std/experimental/allocator/building_blocks/region.d:758`, `deallocateAll()` returns `!_brkInitial || brk(_brkInitial) == 0` and does not assign `_brkCurrent = _brkInitial` on success
- `empty()` later checks whether `_brkCurrent == _brkInitial`, so after a successful reset it can still report non-empty from stale state
- `deallocate()` in `std/experimental/allocator/building_blocks/region.d:1074` determines whether a block is the current tail by comparing against `_brkCurrent`
- After `deallocateAll()` succeeds, stale `_brkCurrent` can still match a previously last allocated block, making `deallocate()` attempt `sbrk(-rounded)` even though the actual break has already been restored
- Runtime reproduction on this host could not exercise the success path because `deallocateAll()` returned false, consistent with the Darwin-specific behavior noted in source, but the success-path bug is directly established by the code on supported Posix targets

## Why This Is A Real Bug
The allocator exposes `deallocateAll()` as a public state-reset operation. A successful reset must restore both the OS-managed break and the allocator's internal cursor. Failing to do so violates the allocator's own invariants: `empty()` no longer reflects actual allocator state, and `deallocate()` can reason about tail ownership using obsolete metadata. This is reachable without undefined behavior assumptions after normal prior allocation and a successful `deallocateAll()`.

## Fix Requirement
When `brk(_brkInitial)` succeeds in `deallocateAll()`, update `_brkCurrent` to `_brkInitial` while still under the mutex.

## Patch Rationale
The patch makes `deallocateAll()` synchronize internal allocator state with the successful kernel-visible break reset by assigning `_brkCurrent = _brkInitial` before returning success. This restores the invariant consumed by `empty()`, `owns()`, and tail-sensitive `deallocate()` logic, and is the minimal change matching the intended allocator semantics.

## Residual Risk
None

## Patch
- `016-sbrkregion-state-stays-stale-after-deallocateall.patch` updates `SbrkRegion.deallocateAll()` in `std/experimental/allocator/building_blocks/region.d` so that a successful `brk(_brkInitial)` also resets `_brkCurrent` to `_brkInitial` under the existing lock