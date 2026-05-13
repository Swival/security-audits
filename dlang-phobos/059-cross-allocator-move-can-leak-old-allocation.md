# Cross-allocator move can leak old allocation

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/fallback_allocator.d:162`
- `std/experimental/allocator/building_blocks/fallback_allocator.d:203`

## Summary
`FallbackAllocator.reallocate` and `FallbackAllocator.alignedReallocate` can succeed by moving an allocation from one backing allocator to the other, but they overwrite the caller's handle even when the source allocator does not implement `deallocate`. In that case the original allocation remains live in the source allocator, the new block is returned to the caller, and the only reference to the old block is lost.

## Provenance
- Verified from the supplied reproducer and source inspection
- Scanner reference: https://swival.dev

## Preconditions
- Cross-allocator `reallocate` path is taken
- Destination allocator allocation succeeds
- Source allocator type does not define `deallocate`

## Proof
The helper `crossAllocatorMove` allocates a new block from the other allocator, copies the payload, conditionally frees the source block only under `hasMember!(From, "deallocate")`, and then unconditionally assigns `b = b1`. Both `reallocate` and `alignedReallocate` call this helper after same-allocator reallocation fails.

With a primary allocator that supports allocation/reallocation but intentionally omits `deallocate`, the following sequence reproduces the bug:
- allocate 8 bytes from the primary allocator
- call `FallbackAllocator!(OneShotNoDeallocate, HeapFallback).reallocate` to grow to 32 bytes
- fallback allocation succeeds, data is copied, and the returned block now points to fallback memory
- the primary allocator still reports its single slot as occupied
- a second primary allocation fails because the original slot was never released

Observed runtime output:
```text
primary.inUse after move=true
second primary allocation length=0
```

## Why This Is A Real Bug
This is a concrete ownership loss, not a theoretical API mismatch. After successful reallocation, the caller has no remaining handle to the source allocation, so it cannot be freed later even if the allocator has some external reclamation mechanism. The reproducer shows persistent capacity loss in the source allocator, proving real resource leakage on a reachable success path.

## Fix Requirement
Reject cross-allocator moves when the source allocator does not implement `deallocate`; return `false` instead of allocating, copying, and replacing the caller's block handle.

## Patch Rationale
The patch in `059-cross-allocator-move-can-leak-old-allocation.patch` makes cross-allocator migration contingent on source-side deallocation support. This preserves the contract that a successful reallocate/alignedReallocate does not orphan the old allocation. Returning failure is the only safe behavior when the old block cannot be released.

## Residual Risk
None

## Patch
`059-cross-allocator-move-can-leak-old-allocation.patch` updates `std/experimental/allocator/building_blocks/fallback_allocator.d` so cross-allocator moves are refused unless the source allocator defines `deallocate`, covering both `reallocate` and `alignedReallocate`.