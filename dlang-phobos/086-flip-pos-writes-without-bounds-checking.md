# flip(pos) lacks bounds validation

## Classification
Validation gap; medium severity; confidence: certain.

## Affected Locations
- `std/bitmanip.d:908`

## Summary
`BitArray.flip(size_t pos)` mutates storage via `bt`/`btr`/`bts` without validating `pos < _len`. Public callers can pass an out-of-range bit index and cause writes outside the logical bit array; for sufficiently large `pos`, this becomes an out-of-bounds read/write into adjacent storage.

## Provenance
The issue was verified by reproduction and patched from the reported finding. Reference: Swival Security Scanner, `https://swival.dev`.

## Preconditions
- `BitArray.flip(pos)` is called with `pos >= _len`.

## Proof
`BitArray.flip(size_t pos)` at `std/bitmanip.d:908` directly executes bit-test and bit-set/reset primitives on `_ptr` using `pos`, but does not assert bounds first.
Other single-bit accessors in the same type validate indices before touching storage, making `flip` an inconsistent unchecked entry point.
Reproduction with LDC shows practical corruption of adjacent storage:
```d
size_t[2] words = [0, 0];
auto ba = BitArray(words[], 1);
ba.flip(64);
assert(words[0] == 0);
assert(words[1] == 1);
```
This demonstrates that a 1-bit `BitArray` can mutate the next machine word when given an unchecked out-of-range position.

## Why This Is A Real Bug
The code path is public and directly reachable by callers. The underlying bit primitives operate on the containing machine word for `pos` and do not perform logical-length checks. As a result, invalid indices can silently corrupt bits beyond the bit array boundary, and large enough indices cross allocated storage boundaries entirely. This is memory-unsafe behavior, not a theoretical API misuse concern.

## Fix Requirement
Add a precondition in `BitArray.flip(size_t pos)` enforcing `assert(pos < _len)` before invoking `bt`, `btr`, or `bts`.

## Patch Rationale
The patch aligns `flip` with existing checked single-bit accessors by rejecting invalid indices before any storage access. This is the minimal, behavior-preserving fix that closes both logical out-of-range mutation and true out-of-bounds access.

## Residual Risk
None

## Patch
Patched in `086-flip-pos-writes-without-bounds-checking.patch` by adding `assert(pos < _len)` at the start of `BitArray.flip(size_t pos)` in `std/bitmanip.d`.