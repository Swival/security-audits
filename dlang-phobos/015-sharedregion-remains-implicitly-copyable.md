# SharedRegion double-frees backing storage on implicit copy

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/region.d:858`
- `std/experimental/allocator/building_blocks/region.d:1505`

## Summary
`SharedRegion` remains implicitly copyable even though its destructor always deallocates the same backing allocation. A plain struct copy duplicates `_impl._begin` and `_impl._end`, so both destructors later call `parent.deallocate(...)` on the same region, causing double-deallocation. The patch disables copying for `SharedRegion` and its borrowed implementation.

## Provenance
- Verified by local reproduction from the reported trigger path
- Scanner reference: https://swival.dev

## Preconditions
- A `SharedRegion` instance is created with a parent allocator that performs deallocation
- The `SharedRegion` is copied before destruction

## Proof
A minimal reproduction with `SharedRegion!(CountingParent)` showed one allocation followed by two deallocations after `auto b = a;` and scope exit:
```text
allocate 103015F70 len=64
copied region
deallocate #1 ptr=103015F70 len=64
deallocate #2 ptr=103015F70 len=64
frees=2
```
This demonstrates that copying preserves the same backing storage metadata and both destructors free the same allocation.

## Why This Is A Real Bug
`SharedRegion` defines `~this()` that unconditionally deallocates its backing store through the parent allocator. Without `@disable this(this)`, ordinary D struct copies are allowed and retain identical ownership state. That creates two live values claiming sole responsibility for one allocation. The observed duplicate `deallocate` calls confirm reachable double-free behavior, which becomes memory corruption risk with real allocators such as `Mallocator`.

## Fix Requirement
Disable postblit/copy for `SharedRegion` and the related borrowed implementation so ownership-bearing region state cannot be duplicated implicitly.

## Patch Rationale
The codebase already treats this ownership model as non-copyable in adjacent types: `InSituRegion` disables copying, and nearby TODOs note that borrowed shared variants should also disable postblits. Applying the same rule to `SharedRegion` and its borrowed implementation removes the invalid aliasing path at the type level and matches the intended lifetime semantics.

## Residual Risk
None

## Patch
Patched in `015-sharedregion-remains-implicitly-copyable.patch`.