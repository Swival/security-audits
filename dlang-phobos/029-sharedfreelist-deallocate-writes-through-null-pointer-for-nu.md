# SharedFreeList null deallocation crashes via null write

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/free_list.d:821`

## Summary
`SharedFreeList.deallocate(void[] b)` admits zero-length blocks when `freeListEligible(0)` is true, but unlike `FreeList.deallocate` it does not special-case `null`. For `b == null`, it casts `b.ptr` to a freelist node and immediately assigns `newRoot.next = _root`, causing a write through address 0.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- A `SharedFreeList` configuration where `freeListEligible(0)` is true, including `SharedFreeList!(Mallocator, 0, 64)`
- `deallocate(null)` is invoked

## Proof
- `SharedFreeList.deallocate(void[] b)` checks eligibility by length, so `b.length == 0` passes when `minSize == 0`
- The function then executes `auto newRoot = cast(shared Node*) b.ptr`
- For `b == null`, `b.ptr` is null, so `newRoot` is null
- The subsequent `newRoot.next = _root` dereferences null and crashes
- This was reproduced with `ldc2` using `shared SharedFreeList!(Mallocator, 0, 64) fl; void[] b = null; fl.deallocate(b);`, which terminated with `Segmentation fault: 11`

## Why This Is A Real Bug
The allocator contract explicitly treats `deallocate(null)` as a supported no-op probe, and the building-block contract expects it to return `true`. The sibling implementation `FreeList.deallocate` already enforces that behavior with an early `b is null` return. `SharedFreeList.deallocate` therefore violates both the documented contract and its own freelist invariant that inserted nodes refer to valid storage.

## Fix Requirement
Reject `null` blocks before freelist insertion and return `true`, mirroring `FreeList.deallocate`.

## Patch Rationale
The patch adds an early `if (b is null) return true;` in `SharedFreeList.deallocate`, before the freelist-node cast and link operation. This preserves documented allocator semantics, aligns `SharedFreeList` with `FreeList`, and removes the null-pointer write without changing behavior for valid blocks.

## Residual Risk
None

## Patch
- Patch file: `029-sharedfreelist-deallocate-writes-through-null-pointer-for-nu.patch`
- Patched location: `std/experimental/allocator/building_blocks/free_list.d:821`