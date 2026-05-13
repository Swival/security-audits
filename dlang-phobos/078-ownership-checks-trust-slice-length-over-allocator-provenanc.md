# Ownership checks trust slice length over allocator provenance

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/experimental/allocator/building_blocks/segregator.d:215`

## Summary
`Segregator.owns(void[] b)` selected `_small` or `_large` solely from `b.length <= threshold`. That trusts caller-controlled slice length instead of allocator provenance. A foreign or resliced allocation can therefore be checked against the wrong backing allocator and produce a false ownership result.

## Provenance
- Verified from the provided reproducer and source inspection in `std/experimental/allocator/building_blocks/segregator.d`
- Reference: https://swival.dev

## Preconditions
- Caller passes a slice whose current length does not reflect the allocator that originally produced the allocation
- This is reachable with ordinary reslicing, including shrinking a large allocation below `threshold`

## Proof
- `owns(void[] b)` routed by length: `b.length <= threshold ? _small.owns(b) : _large.owns(b)`
- `resolveInternalPointer` in the same type already uses the correct provenance pattern by checking `_small` first and then `_large`, instead of trusting size
- Reproducer used `Segregator!(128, BitmappedBlock!(4096), BitmappedBlock!(4096))`
- After allocating `200` bytes from the large side and reslicing to `64`, observed:
  - `seg owns original = yes`
  - `large owns original = yes`
  - `seg owns shrunk = no`
  - `large owns shrunk = yes`
- The same live allocation becomes falsely unowned solely because the caller changed slice length through the public API

## Why This Is A Real Bug
Ownership checks are security- and correctness-relevant predicates. Here the predicate is observably wrong for a live allocation, with no undefined behavior or privileged setup required. The caller can cross the trust boundary by presenting a valid slice whose metadata was changed through normal language operations, causing `Segregator` to consult the wrong allocator and misreport ownership.

## Fix Requirement
`owns` must determine ownership by allocator provenance rather than current slice length. A correct fix is to query both sub-allocators, or otherwise use provenance data independent of mutable slice metadata.

## Patch Rationale
The patch changes `Segregator.owns` to follow the same provenance-safe pattern already used by `resolveInternalPointer`: check one sub-allocator and, on failure, check the other. This removes the trust in `b.length` as a routing oracle and ensures resliced allocations are still recognized by the allocator that actually owns them.

## Residual Risk
None

## Patch
- Patched file: `078-ownership-checks-trust-slice-length-over-allocator-provenanc.patch`
- Change: update `std/experimental/allocator/building_blocks/segregator.d` so `owns(void[] b)` queries both `_small` and `_large` instead of dispatching by `b.length`
- Effect: a large allocation resliced below `threshold` still reports as owned by `Segregator`, eliminating the reproduced false negative