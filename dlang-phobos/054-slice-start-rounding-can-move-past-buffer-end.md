# Slice start rounding can move past buffer end

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/common.d:236`

## Summary
`roundStartToMultipleOf(void[] s, uint base)` rounds the slice start pointer up, then unconditionally returns `p[0 .. end - p]`. When `s` is non-empty and the rounding gap is larger than `s.length`, the computed `p` exceeds `end`. The unchecked `end - p` then underflows to a large `size_t`, producing a forged slice whose start lies past the original buffer and whose length spans unrelated memory.

## Provenance
- Verified from the provided reproducer and source inspection
- Reference: https://swival.dev

## Preconditions
- Non-empty input slice
- `base != 0`
- Rounded start pointer exceeds the original slice end

## Proof
The vulnerable helper computes:
```d
auto p = roundUpToMultipleOf(cast(size_t) s.ptr, base);
auto end = cast(size_t) s.ptr + s.length;
return p[0 .. end - p];
```

For a non-empty slice where the next `base` boundary lies beyond `end`, `p > end`. The subtraction `end - p` is performed on `size_t`, so it wraps to a very large positive value. The returned `void[]` therefore has:
- a start pointer past the original allocation, and
- a huge forged length derived from unsigned underflow.

This behavior was reproduced directly. The current in-tree callers observed during verification appear constrained enough not to trigger the bug today, but the helper itself is directly reachable and malformed for valid caller-controlled inputs satisfying the stated preconditions.

## Why This Is A Real Bug
This is not a theoretical edge case. The function accepts arbitrary slices and a caller-controlled rounding base, and it fails to preserve the basic slice invariant that the start must not exceed the end. Once the forged slice is returned, later code can perform reads or writes that appear in-bounds relative to that slice while actually operating out of bounds on the original buffer. The bug exists independently of whether current bundled call sites happen to avoid the bad state.

## Fix Requirement
Guard the post-rounding pointer before creating the result slice. If the rounded start is at or beyond the original end, return an empty or null slice instead of forming `p[0 .. end - p]`.

## Patch Rationale
The patch adds an explicit `p >= end` check before slicing and returns an empty result in that case. This matches the intended helper semantics: rounding the start forward should yield the remaining aligned sub-slice, and if no bytes remain after rounding, the correct result is an empty slice. The change removes the unsigned underflow and prevents construction of an invalid slice.

## Residual Risk
None

## Patch
Saved as `054-slice-start-rounding-can-move-past-buffer-end.patch`.