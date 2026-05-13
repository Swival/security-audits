# Input-range rollback invariant breaks after moved reallocation

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/package.d:1489`
- `std/experimental/allocator/package.d:2252`

## Summary
`expandArray(..., ref T[] array, R range)` promises that on failure the caller's array is unchanged. In the non-forward input-range path, repeated `reallocate` calls can move `buf` before a later allocation failure. When that later failure occurs, the implementation writes `array = cast(T[]) buf; return false;`, exposing the moved, partially expanded slice to the caller despite returning failure.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Scanner reference: https://swival.dev

## Preconditions
- `range` is a non-forward input range
- At least one earlier `reallocate` succeeds and moves the buffer
- A later `reallocate` fails

## Proof
- In the non-forward input-range branch, growth proceeds incrementally with `alloc.reallocate(buf, ...)`.
- A successful `reallocate` may replace `buf.ptr` with a different allocation.
- The code then constructs the newly appended element and continues.
- If a subsequent `reallocate` fails, the failure path assigns `array = cast(T[]) buf;` and returns `false`.
- The reproduced PoC allocator caused:
  - first `reallocate`: success with move
  - second `reallocate`: failure
- Observed behavior:
  - `expandArray` returned `false`
  - caller-visible `arr.ptr` changed
  - caller-visible `arr.length` changed from `1` to `2`

## Why This Is A Real Bug
The function's failure contract is rollback-like: failure must not mutate the caller's slice. Under the reproduced sequence, failure still commits prior successful growth into the caller-visible `array`. That breaks API invariants and can mislead callers into treating the result as unchanged, including subsequent use, cleanup, or retry logic against a partially committed buffer.

## Fix Requirement
On any failing path in the non-forward input-range expansion logic, do not publish intermediate `buf` state to the caller. Preserve the original caller slice on `false`, or otherwise guarantee true rollback semantics for all prior successful reallocations.

## Patch Rationale
The patch removes the failure-path publication of the local grown buffer and preserves the original `array` when a later incremental reallocation fails. This aligns observable behavior with the documented failure contract while keeping successful growth behavior unchanged.

## Residual Risk
None

## Patch
- Patched in `009-input-range-array-growth-leaves-caller-slice-stale-after-suc.patch`
- The patch ensures the non-forward input-range failure path no longer updates the caller slice with partially expanded storage before returning `false`.