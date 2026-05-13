# replaceSlice dereferences empty slice pointers

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/array.d:2532`
- `std/array.d:3519`

## Summary
`replaceSlice` accepts some zero-length slices under its existing overlap contract, then unconditionally evaluates `&slice[0]` while computing the replacement offset. For accepted empty slices such as `a[0 .. 0]`, `null`, and `[]`, this violates the array-bounds invariant before any replacement logic runs and causes a runtime failure instead of a valid insertion-style replacement.

## Provenance
- Reproduced from the verified finding and patched in `021-replaceslice-dereferences-empty-slice-pointers.patch`
- Scanner source: https://swival.dev

## Preconditions
- `slice.length == 0`
- `slice` is passed to `replaceSlice`
- `overlap(s, slice) is slice` holds for that empty slice

## Proof
- Existing tests show `overlap(a, a[0 .. 0]) is a[0 .. 0]` and `overlap(null, x) is null`, so some empty slices satisfy the function contract and reach `replaceSlice`.
- The function then computes the offset using `&slice[0] - &s[0]` at `std/array.d:3519`.
- For `slice.length == 0`, `slice[0]` is invalid by definition.
- Reproduction with `ldc2` triggers `core.exception.ArrayIndexError@./std/array.d(3519): index [0] is out of bounds for array of length 0`.
- A reachable example is `replaceSlice(a, a[0 .. 0], [9])`, which passes the contract and then crashes.

## Why This Is A Real Bug
The crash occurs on a normal safe call path that satisfies the documented overlap precondition for certain empty subslices. This is not a rejected-input case: the function admits the argument, then breaks its own internal invariant during offset calculation. That makes the issue a real reachable denial-of-service/runtime safety bug in committed code.

## Fix Requirement
Handle zero-length `slice` before any `slice[0]` pointer math. Compute the offset from `slice.ptr` only when valid for empty-slice handling, or otherwise branch explicitly so empty accepted slices are treated as insertion points without indexing.

## Patch Rationale
The patch adds an explicit empty-slice path before offset computation, avoiding any dereference of `slice[0]`. This preserves existing behavior for non-empty slices while making accepted zero-length inputs behave safely and consistently with insertion-like replacement semantics.

## Residual Risk
None

## Patch
- Patched in `021-replaceslice-dereferences-empty-slice-pointers.patch`
- The change guards the zero-length case before offset calculation in `std/array.d`
- Non-empty slice behavior remains unchanged; only the invalid empty-slice dereference path is removed