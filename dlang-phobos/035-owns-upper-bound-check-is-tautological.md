# owns upper-bound check is tautological

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/ascending_page_allocator.d:40`

## Summary
`AscendingPageAllocator.owns` used the caller-controlled `buf.ptr` as the base for its upper-bound check. The condition effectively evaluated `buf.ptr < buf.ptr + numPages * pageSize`, which is tautologically true for any non-null pointer when the allocator spans a positive number of pages. As a result, any pointer at or above `data` could be reported as owned even when it lies outside the allocator's reserved virtual-address range.

## Provenance
- Reproduced from the verified finding and contract review in the affected source.
- Public reachability and wrapper forwarding confirmed in `std/experimental/allocator/package.d:2925` and `std/experimental/allocator/package.d:3155`.
- Reference: https://swival.dev

## Preconditions
- Allocator is initialized.
- Caller passes a non-null buffer pointer.

## Proof
The buggy predicate compared:
```d
buf.ptr >= data && buf.ptr < buf.ptr + numPages * pageSize
```

For any non-null `buf.ptr` and positive `numPages * pageSize`, the right-hand clause is true because it compares a pointer to itself plus a positive offset. The only effective gate is therefore `buf.ptr >= data`.

This violates the documented `owns` contract in `std/experimental/allocator/building_blocks/ascending_page_allocator.d:175` and `std/experimental/allocator/building_blocks/ascending_page_allocator.d:432`, which requires checking whether the buffer lies within the allocator's virtual-address range.

The bug is reachable through direct public `owns` calls and wrapper forwarding, and it influences ownership-based dispatch in:
- `std/experimental/allocator/building_blocks/fallback_allocator.d:140`
- `std/experimental/allocator/building_blocks/fallback_allocator.d:179`
- `std/experimental/allocator/building_blocks/fallback_allocator.d:216`
- `std/experimental/allocator/building_blocks/fallback_allocator.d:268`
- `std/experimental/allocator/building_blocks/allocator_list.d:464`
- `std/experimental/allocator/building_blocks/allocator_list.d:485`
- `std/experimental/allocator/building_blocks/allocator_list.d:500`

## Why This Is A Real Bug
Ownership checks are used to decide which allocator may service `expand`, `reallocate`, and `deallocate`. A false positive from `AscendingPageAllocator.owns` can misroute operations for memory outside its reservation, breaking allocator ownership invariants. In downstream paths, that can lead to decommit or related page-management actions being issued against the wrong address range.

## Fix Requirement
Replace the upper bound with the allocator's actual end address: compare against `data + numPages * pageSize`, not `buf.ptr + numPages * pageSize`.

## Patch Rationale
The fix restores the intended half-open interval check `[data, data + numPages * pageSize)`. This matches the documented contract, removes caller influence from the upper bound, and re-establishes correct ownership-based dispatch for wrapped allocator operations.

## Residual Risk
None

## Patch
```diff
--- a/std/experimental/allocator/building_blocks/ascending_page_allocator.d
+++ b/std/experimental/allocator/building_blocks/ascending_page_allocator.d
@@
-        return buf.ptr >= data && buf.ptr < buf.ptr + numPages * pageSize ? Ternary.yes : Ternary.no;
+        return buf.ptr >= data && buf.ptr < data + numPages * pageSize ? Ternary.yes : Ternary.no;
```