# Size-based deallocate can free through wrong allocator

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/segregator.d:223`

## Summary
`Segregator.deallocate` selected `_small` or `_large` solely from `data.length <= threshold`. That dispatch used the caller-visible slice length instead of allocation provenance, so a valid allocation could be sent to the wrong backing allocator after the slice was shortened. In reproduced behavior, this caused the region allocator ownership check to reject the foreign pointer, leading to an assertion in debug builds or a failed free/leak in non-asserting paths.

## Provenance
- Verified from the provided finding and reproducer against the codebase under review
- Reference: https://swival.dev

## Preconditions
- Different backing allocators can produce same-length slices
- A caller deallocates a previously returned allocation using a shortened slice whose current length crosses the segregator threshold

## Proof
`Segregator.allocate` chooses `_small` or `_large` from the requested size, but `Segregator.deallocate` at `std/experimental/allocator/building_blocks/segregator.d:223` used only the current `data.length` to choose the target allocator. A block originally allocated on the large side can therefore be deallocated through `_small` after the caller shortens the slice below `threshold`. The reproducer showed this concretely with region-backed allocators: the receiving allocator checks ownership and rejects the foreign pointer, asserting in debug configurations or returning failure without freeing in non-debug behavior. The issue is reachable from the public `allocate` and `deallocate` API surface. The claimed direct public `reallocate` shrinking path was not reproduced because the cross-threshold `reallocate` flow allocates on the destination side and deallocates the original block before updating the slice.

## Why This Is A Real Bug
Allocator correctness depends on freeing through the allocator that owns the allocation. Dispatching from mutable slice length violates that provenance rule because slice length is not a stable ownership identifier. The resulting behavior is observable and harmful: assertion failures, failed frees, and leaks. This is not a theoretical mismatch; it occurs with valid API usage where the caller passes a shortened view of an allocated block.

## Fix Requirement
`deallocate` must determine the owning allocator from provenance, not from the current slice length. Acceptable fixes include checking `owns` on both sides or storing origin metadata and dispatching from that metadata.

## Patch Rationale
The patch updates `Segregator` deallocation logic to stop relying on `data.length` and instead use allocator ownership to select the correct backing allocator before freeing. That aligns deallocation with actual allocation provenance and prevents shortened slices from being misrouted across the threshold boundary.

## Residual Risk
None

## Patch
- `077-size-based-deallocate-can-free-through-wrong-allocator.patch`