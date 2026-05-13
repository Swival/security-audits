# ScopedAllocator unlink-before-free orphans live allocation

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/scoped_allocator.d:148`

## Summary
`ScopedAllocator.deallocate` removed the block from its internal linked list before delegating to `parent.deallocate`. When the parent returned `false` and kept the allocation live, `ScopedAllocator` had already lost the only reference used by `deallocateAll()`. A later bulk cleanup skipped the still-live block, cleared `root`, and permanently orphaned the allocation.

## Provenance
- Verified from the provided reproducer and code path analysis
- Source under review: `std/experimental/allocator/building_blocks/scoped_allocator.d`
- Reference: https://swival.dev

## Preconditions
- The parent allocator may return `false` from `deallocate` while leaving the allocation live
- The allocation was previously linked into `ScopedAllocator.root`
- A caller invokes `deallocate` on that block before `deallocateAll()`

## Proof
- `allocate` links each prefixed block into `root`
- In `ScopedAllocator.deallocate`, the implementation unlinked `parent.prefix(b)` from `root` before calling `parent.deallocate(b)`
- If `parent.deallocate(b)` returned `false`, the parent still owned a live allocation, but `root` no longer referenced it
- A subsequent `deallocateAll()` iterated only the remaining `root` list, skipped the orphaned live block, then set `root = null`
- The reproducer confirmed this state transition:
  - `deallocate(oldest)` returned `false`
  - `scoped.empty` became true after `deallocateAll()`
  - the underlying parent region remained non-empty
- This demonstrates a real stale live allocation that is no longer tracked by `ScopedAllocator`

## Why This Is A Real Bug
The allocator contract permits `deallocate` failure without implying the block was freed. Removing bookkeeping before observing that result breaks `ScopedAllocator`'s ownership invariant: every live allocation must remain reachable from `root` until successfully released. Once that invariant is broken, wrapper state becomes incorrect and bulk cleanup can no longer reclaim the live allocation.

## Fix Requirement
Only unlink a block from `root` after `parent.deallocate(b)` succeeds. If deallocation fails, preserve list membership exactly as-is so later cleanup and emptiness checks remain correct.

## Patch Rationale
The patch reorders operations in `ScopedAllocator.deallocate` so parent deallocation is attempted first and list unlinking happens only on success. This preserves tracked ownership on failure, keeps `deallocateAll()` able to reach the block, and aligns wrapper state with the parent allocator's actual live allocations.

## Residual Risk
None

## Patch
- Patched in `066-deallocate-unlinks-before-parent-failure-causing-stale-live-.patch`
- Change applied to `std/experimental/allocator/building_blocks/scoped_allocator.d:148`
- Effective behavior:
  - if `parent.deallocate(b)` returns `true`, the block is unlinked from `root`
  - if `parent.deallocate(b)` returns `false`, the block remains linked and recoverable by `deallocateAll()`