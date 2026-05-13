# Static-array `cycle` can outlive source array

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/range/package.d:2528`
- `std/range/package.d:4667`
- `std/range/package.d:4669`
- `std/range/package.d:4673`
- `std/range/package.d:4677`
- `std/range/package.d:4701`
- `std/range/package.d:4703`
- `std/range/package.d:4705`

## Summary
The public overload `cycle(ref R input, size_t index = 0)` accepts static arrays and stores `input.ptr` inside `Cycle!(T[N])`. The resulting range has no lifetime tie to `input`, so if the `Cycle` escapes the source scope it dereferences a dangling pointer to dead stack storage through `front`, `opIndex`, `save`, and `opSlice(i, $)`.

## Provenance
- Verified from the reported implementation and reproduced locally against `std/range/package.d`
- Scanner source: https://swival.dev

## Preconditions
- `cycle` is called on a local static array
- The returned or saved `Cycle!(T[N])` escapes the array's scope

## Proof
- At `std/range/package.d:2528`, the static-array overload of `cycle(ref R input, size_t index = 0)` is reachable through the public API.
- At `std/range/package.d:4667`, `std/range/package.d:4669`, and `std/range/package.d:4673`, `Cycle!(T[N])` operations dereference the stored raw pointer.
- At `std/range/package.d:4677`, `save` preserves the same pointer without restoring any ownership or lifetime guarantee.
- At `std/range/package.d:4701`, `std/range/package.d:4703`, and `std/range/package.d:4705`, `opSlice(i, $)` constructs another `Cycle` from the same pointer.
- Reproducer: a small program returned `cycle(local)` where `local` was `int[4] = [11, 22, 33, 44]`. Reading the escaped range in the caller produced corrupted values such as `1834903264,1,2,0`; after stack clobbering, reads changed again (`front=1873569488`, `idx1=0`), confirming post-return access to reused stack memory.

## Why This Is A Real Bug
This is a concrete use-after-scope on stack memory. The range object remains usable after the backing static array is gone, and subsequent reads observe stale or corrupted stack contents. Because the implementation exposes mutable element access via pointer-based operations, the bug can also write into invalid stack storage in `@system` code. The issue is externally reachable through a documented public overload and does not depend on undefined caller casts or private API misuse.

## Fix Requirement
The static-array path must not create a `Cycle` that borrows raw storage beyond the source lifetime. The fix must either:
- reject or disable the static-array overload for escaping use, or
- copy the static array into owned storage before constructing the cycling range

## Patch Rationale
The patch removes the unsafe escaping behavior for static arrays by preventing `cycle(ref R)` from handing out a pointer-backed `Cycle!(T[N])` that outlives `input`. This directly eliminates the dangling-pointer state instead of attempting to document lifetime expectations that the type system does not enforce.

## Residual Risk
None

## Patch
- `019-static-array-cycle-can-outlive-source-array.patch`