# reserve bitwise-reallocates destructible elements

## Classification
- Type: resource lifecycle bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/container/array.d:445`

## Summary
`Array.reserve` forwards growth to `Payload.reserve`, which relocates initialized elements with `memcpy` or `realloc`-style behavior. For `T` with destruction semantics, this performs a raw bitwise move of live objects without invoking move/copy construction, but later teardown and shrink paths still call destructors on the relocated instances. This violates object lifetime rules and can corrupt self-referential or elaborate-move state.

## Provenance
- Verified from the reported source location in `std/container/array.d:445`
- Reproduced from the provided scenario and source-grounded reasoning
- Reference: https://swival.dev

## Preconditions
- `Array` stores non-trivially destructible `T`
- The array grows beyond current capacity, causing `reserve` to relocate elements

## Proof
- `Array.reserve` reaches `Payload.reserve` at `std/container/array.d:445`
- Existing elements are relocated with raw memory movement (`memcpy` / realloc-style transfer), not element-wise move or copy construction
- `Payload.~this` and shrink/destroy paths conditionally run destructors when `__traits(needsDestruction, T)`
- Therefore, after reallocation, destructors run on instances at the new address that were never properly reconstructed there
- The reproducer shows teardown alone is sufficient to invoke `S.~this` on corrupted relocated state
- Related library code in `std/algorithm/mutation.d` already treats such raw moves as unsafe for self-referential structs and guards them instead of permitting blind relocation

## Why This Is A Real Bug
The bug is not theoretical: the container moves live objects in a way that bypasses their required move semantics, then later destroys them as if construction at the destination had occurred. For destructor-bearing or self-referential structs, raw relocation can invalidate internal pointers or ownership state. Subsequent reads, writes, shrink, or final teardown can then observe corrupted state or trigger memory-unsafe destruction behavior.

## Fix Requirement
When `__traits(needsDestruction, T)` applies, reserve growth must not bitwise-relocate initialized elements. It must allocate new storage, construct destination elements with move/emplace semantics, and then destroy the old instances before releasing prior storage.

## Patch Rationale
The patch in `063-reserve-bitwise-reallocates-destructible-elements.patch` changes the growth path for destructible element types to use typed relocation instead of raw byte movement. This preserves lifetime invariants by reconstructing each element in new storage and only then destroying the old copies, while leaving the existing fast path intact for trivially relocatable cases.

## Residual Risk
None

## Patch
- `063-reserve-bitwise-reallocates-destructible-elements.patch` updates `std/container/array.d` so `reserve` no longer uses bitwise reallocation for destructible element types
- The patched path allocates fresh backing storage, relocates elements individually, destroys the old instances, and then swaps storage
- This aligns `Array` growth behavior with the destruction-aware semantics already assumed elsewhere in the container implementation