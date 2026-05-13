# Empty slice remaps mmfile due to unsigned end-index underflow

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/mmfile.d:486`

## Summary
`opSlice(i1, i2)` forwards slice bounds to `ensureMapped(i1, i2)`. For an empty slice with `i == j == 0`, `ensureMapped` evaluates `j - 1` before any emptiness check. Because `j` is unsigned, this underflows and corrupts the range-to-mapping calculation. The reachable public call `mmfile[0 .. 0]` therefore performs an unnecessary unmap/remap and changes mapping state for an empty range.

## Provenance
- Verified from the provided finding and local reproduction against the committed code
- Swival Security Scanner: https://swival.dev

## Preconditions
- Caller requests an empty slice with `j == 0`
- The `mmfile` instance already has an active mapping whose state can be observed changing

## Proof
The vulnerable path is in `std/mmfile.d:486`, where `ensureMapped(i, j)` computes values derived from `j - 1` without first handling `i == j`.

Observed reproduction:
- Accessing an offset beyond the first window establishes a larger mapping state
- Calling `mmf[0 .. 0]` then triggers `jblock = (j - 1) / window`
- With `j == 0`, unsigned subtraction underflows, making the remap condition true
- The code unmaps the current region and remaps a smaller region, even though the requested slice is empty

Concrete runtime result from the reproducer:
- Prior state after indexing at `page + 1`: `map(0, 49152)`
- After empty slice `mmf[0 .. 0]`: `map(0, 16384)`

This demonstrates that an empty slice mutates mapping state.

## Why This Is A Real Bug
Empty slices must preserve mapping invariants and behave as a no-op for backing-map state. Here, a public API call for an empty range causes a state transition driven by wrapped unsigned arithmetic rather than the requested bounds. Even though `map` later clamps length and prevents mapping the literal maximum offset in the reproduced path, the invariant violation is still real: empty-range access changes mappings, performs unnecessary unmap/remap work, and can shrink an existing valid mapping.

## Fix Requirement
Add an early return in `ensureMapped(i, j)` for the empty-range case `i == j`, before any use of `j - 1` or block calculations derived from it.

## Patch Rationale
The patch in `024-empty-slice-underflows-end-index-before-mapping.patch` implements the minimal invariant-preserving fix: detect empty slices at entry to `ensureMapped(i, j)` and return immediately. This prevents unsigned underflow, preserves existing mapping state for empty slices, and avoids unnecessary remapping side effects without changing non-empty range behavior.

## Residual Risk
None

## Patch
`024-empty-slice-underflows-end-index-before-mapping.patch` adds an early empty-slice guard in `ensureMapped(i, j)` in `std/mmfile.d` so `j - 1` is never evaluated when `i == j`.