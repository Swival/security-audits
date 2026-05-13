# Requested size rounding overflow yields overlapping allocation

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/kernighan_ritchie.d:566`

## Summary
`goodAllocSize` rounded requested sizes up to allocator alignment with `roundUpToMultipleOf(alignment)` and did not reject arithmetic overflow. For requests near `size_t.max`, the rounded size could wrap to a smaller value, including zero. `allocate(size_t)` then used that wrapped size for allocator bookkeeping while still returning `result[0 .. n]` to the caller, producing an invalid oversized slice and enabling overlapping subsequent allocations from unchanged allocator state.

## Provenance
- Verified from the supplied reproducer and patch requirements against `std/experimental/allocator/building_blocks/kernighan_ritchie.d`
- Scanner source: https://swival.dev

## Preconditions
- Caller can request an allocation size near `size_t.max`

## Proof
- `allocate` and `deallocate` route caller-controlled lengths through `goodAllocSize`.
- `goodAllocSize` previously returned `n.roundUpToMultipleOf(alignment)` with no overflow check.
- When `n == size_t.max` and alignment is `size_t.sizeof`, rounding wraps to `0`.
- In the reproduced case, `actualBytes` became `0`, `newRoot` was computed as `result + actualBytes`, and allocator state did not advance.
- The function still returned `result[0 .. n]`, specifically a non-null slice of length `18446744073709551615`.
- A subsequent `allocate(32)` returned the same pointer, confirming overlapping allocation from unchanged state.

## Why This Is A Real Bug
The bug is externally reachable via the public allocator API and violates the allocator's core size/accounting invariant: the internal consumed size can be smaller than the externally reported allocation. The reproduced behavior shows both impacts directly:
- the caller receives an out-of-bounds slice claim far larger than backing storage
- the allocator reissues the same memory to later callers, creating overlapping live allocations

This is concrete memory unsafety, not a theoretical integer-wrap concern.

## Fix Requirement
Reject requests whose alignment rounding would overflow before returning from `goodAllocSize`, so allocation and deallocation bookkeeping only operate on representable aligned sizes.

## Patch Rationale
The patch in `037-requested-size-rounding-can-overflow-to-a-too-small-allocati.patch` adds an overflow guard in `goodAllocSize` before alignment rounding. That preserves the invariant that aligned allocation sizes are monotonic, non-wrapping, and large enough to cover the caller-visible slice length used by allocator bookkeeping.

## Residual Risk
None

## Patch
`037-requested-size-rounding-can-overflow-to-a-too-small-allocati.patch` fixes `std/experimental/allocator/building_blocks/kernighan_ritchie.d` by rejecting sizes whose aligned rounding would overflow instead of returning a wrapped allocation size.