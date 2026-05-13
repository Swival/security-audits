# ContiguousFreeList leaks parent-allocated support block

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/free_list.d:518`
- `std/experimental/allocator/building_blocks/free_list.d:753`

## Summary
`ContiguousFreeList` allocates a contiguous support block from a non-`NullAllocator` parent during construction, but never releases that block during object destruction. The originally reported overwrite theory is not supported by source behavior; the reproduced bug is the missing destruction path for `support`.

## Provenance
- Verified by local source review and runtime reproduction
- Scanner reference: https://swival.dev

## Preconditions
- Use a stateful, allocating parent allocator
- Construct `ContiguousFreeList` through an allocating constructor path
- Allow the allocator instance to go out of scope without manually reclaiming the parent-allocated support block

## Proof
- The constructor path at `std/experimental/allocator/building_blocks/free_list.d:518` allocates backing storage from `parent` and initializes the free list from that memory.
- `deallocateAll` at `std/experimental/allocator/building_blocks/free_list.d:753` resets free-list state and forwards `deallocateAll` to the parent allocator, but does not call `parent.deallocate(support)`.
- No `~this` destructor exists to free `support` when the allocator itself is destroyed.
- Runtime reproduction with a counting parent allocator showed `allocs=1 deallocs=0 bytesLive=1024` after a `ContiguousFreeList!(CountingAllocator, 64, 64)` instance went out of scope, confirming the support block remained live.

## Why This Is A Real Bug
The type acquires ownership of parent-allocated memory during construction and exposes no matching release on destruction. This causes a persistent leak for any parent allocator that requires explicit `deallocate`, even when the free list itself is otherwise used correctly. `deallocateAll` is insufficient because it only resets allocator state; it does not return the contiguous support block to the parent.

## Fix Requirement
Add a destruction path that deallocates `support` back to `parent` for non-`NullAllocator` configurations, while preserving existing free-list teardown behavior and avoiding double free.

## Patch Rationale
The patch adds explicit cleanup for the support block owned by `ContiguousFreeList`. This matches the actual resource lifetime: constructors allocate `support`, so destruction must release it. The fix targets the proven leak directly rather than the unsupported claim that constructor assignment overwrites ownership metadata.

## Residual Risk
None

## Patch
The patch in `028-contiguousfreelist-constructors-lose-ownership-of-allocated-.patch` adds destructor-based reclamation of the parent-allocated support block in `std/experimental/allocator/building_blocks/free_list.d`, ensuring `support` is returned to `parent` exactly once when a `ContiguousFreeList` instance is destroyed.