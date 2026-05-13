# Constructor leaks kernel buffer on object destruction

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/numeric.d:1994`

## Summary
`GapWeightedSimilarityIncremental.this` allocates `kl` with `malloc` when any match exists, but object destruction does not release that buffer. The only existing free path is `empty()`, and it frees only after iteration is fully exhausted. Destroying the object after reading `front` or stopping iteration early leaks the heap allocation.

## Provenance
- Verified from the provided reproducer and source analysis
- Scanner reference: https://swival.dev

## Preconditions
- Construct and destroy `GapWeightedSimilarityIncremental` without calling `empty()`
- At least one match exists, so constructor allocation of `kl` occurs
- The instance is dropped before iteration is fully exhausted

## Proof
- `GapWeightedSimilarityIncremental.this` allocates `kl` via `malloc(s.length * t.length * F.sizeof)` after discovering a match at `std/numeric.d:1994`
- The existing release path is inside `empty()`, which frees only when `currentValue == 0`
- While a current match exists, `empty()` returns `false` and does not free the buffer
- Normal use is enough to trigger the leak: `auto simIter = gapWeightedSimilarityIncremental(["Hello"], ["Hello"], 0.5); assert(simIter.front == 1);` then let scope exit
- Range-style early termination also leaks because `front`/`popFront` can be used without ever reaching the freeing branch in `empty()`

## Why This Is A Real Bug
The allocation is manual heap memory, not GC-managed storage. Its lifetime currently depends on callers fully exhausting the iterator and invoking the specific freeing branch in `empty()`. That is not a valid ownership model for a value type with normal scope destruction semantics. Early scope exit is routine and deterministically leaks memory proportional to `s.length * t.length * F.sizeof`.

## Fix Requirement
Add destruction-time cleanup that frees `kl` when it is non-null, independent of whether iteration reached `empty()`.

## Patch Rationale
The patch adds a destructor for `GapWeightedSimilarityIncremental` that frees `kl` if present. This matches the constructor’s ownership behavior, closes the leak on ordinary scope exit, and preserves the existing `empty()` fast path because freeing a null pointer is avoided by the same non-null guard.

## Residual Risk
None

## Patch
- Patch file: `023-constructor-leaks-kernel-buffer-on-object-destruction.patch`
- Implemented change: add a destructor in `std/numeric.d` that releases `kl` when non-null