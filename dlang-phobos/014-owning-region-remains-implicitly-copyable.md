# Owning Region remains implicitly copyable

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/region.d:97`

## Summary
`Region` is an owning type with a destructor that always returns its backing slice to `parent`, but it remains implicitly copyable. A by-value copy duplicates the same `_impl` state, so multiple destructors deallocate the same allocation, causing double-free or allocator state corruption.

## Provenance
- Verified by local reproduction with `ldc2`
- Upstream source review in `std/experimental/allocator/building_blocks/region.d`
- Reference: https://swival.dev

## Preconditions
- A `Region` value is copied before destruction

## Proof
- `Region.~this` unconditionally calls `parent.deallocate(_begin[0 .. _end - _begin])`, making the type ownership-bearing.
- The implementation leaves copying enabled; the source itself notes that the postblit should be disabled because such objects must not be copied naively.
- Reproduction compiled and ran successfully with a PoC that both assigns `auto r2 = r1;` and passes `r1` by value into a sink taking `Region!TrackingAllocator`.
- Execution aborts on the second destructor-driven deallocation with `TrackingAllocator.deallocate: double deallocate of same region backing store`.
- The stack attributes the failing second release to `std.experimental.allocator.building_blocks.region.Region...__dtor()`.
- With real parents such as `Mallocator`, the same path reaches `std/experimental/allocator/mallocator.d:41`, where `deallocate` frees `b.ptr`, so the duplicated owner can double-free heap memory.

## Why This Is A Real Bug
`Region` is not a view; it owns a single backing allocation and frees it in its destructor. Copying an owning value without transfer semantics creates aliased ownership of the same allocation. Since each copy runs the same destructor, the bug deterministically produces a second deallocation once both values leave scope. This is directly reachable through ordinary language features: assignment, argument passing by value, and returns.

## Fix Requirement
Disable copying for `Region` so ownership cannot be duplicated implicitly, e.g. by adding `@disable this(this);`.

## Patch Rationale
The patch makes `Region` non-copyable at the type level, matching its destructor-based ownership model and the file's existing intent comment. Preventing copies is the narrowest correct fix because it stops double-destruction before runtime and preserves existing destruction behavior for the single owner.

## Residual Risk
None

## Patch
```diff
--- a/std/experimental/allocator/building_blocks/region.d
+++ b/std/experimental/allocator/building_blocks/region.d
@@
     private RegionImpl _impl;
 
+    @disable this(this);
+
     @property ParentAllocator parent()
     {
         return cast(ParentAllocator) _impl._begin;
```