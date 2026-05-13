# Increment helper writes through empty slice

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/internal/math/biguintx86.d:211`

## Summary
`multibyteIncrementAssign` dereferenced `dest.ptr` before validating `dest.length`. When called with an empty `uint[]`, the x86 asm path still executed a write to `[EDX]`, violating the empty-slice no-access invariant and enabling an out-of-bounds write relative to the provided slice.

## Provenance
- Verified finding reproduced from scanner output
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- `multibyteIncrementAssign` is called with `dest.length == 0`

## Proof
- The function takes public input `uint[] dest` and `uint carry`.
- In `std/internal/math/biguintx86.d:211`, the asm prologue loads `dest.length` into `ECX` and `dest.ptr` into `EDX`.
- Control then enters the main loop unconditionally and performs `add [EDX], EAX` or `sub [EDX], EAX` before any zero-length guard.
- D empty slices retain a pointer value; the reproduced case used `a[0 .. 0]`, whose `.ptr` equals `a.ptr`.
- Reproducer:
```d
uint[] a = [0x12345678];
multibyteIncrementAssign!('+')(a[0 .. 0], 1);
assert(a[0] == 0x12345679); // mutated through an empty slice
```
- This demonstrates write reachability through an empty slice and corruption outside the slice bounds.

## Why This Is A Real Bug
The language invariant for empty slices is that no element access is permitted. Here, a zero-length slice still triggers a memory write through its retained pointer, so the callee mutates storage that is not within the caller-provided slice. The reproduced mutation of `a[0]` from `a[0 .. 0]` confirms concrete, observable misbehavior and out-of-bounds write semantics relative to the API contract.

## Fix Requirement
Add an early return before any pointer use: when `dest.length == 0`, return `carry & 1` immediately and skip the asm body entirely.

## Patch Rationale
The carry result for a zero-word increment is fully determined by the low bit of `carry`; no destination word exists to absorb it. Guarding on `dest.length == 0` before touching `dest.ptr` preserves existing behavior for non-empty slices and eliminates the invalid dereference on the empty-slice path.

## Residual Risk
None

## Patch
Applied in `043-increment-helper-writes-through-empty-slice.patch` by inserting a zero-length fast path at the top of `multibyteIncrementAssign` in `std/internal/math/biguintx86.d`, returning `carry & 1` before entering the x86 asm block.