# Raw `void[]` constructor permits misaligned `size_t` access

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/bitmanip.d:671`

## Summary
The public constructor `BitArray.this(void[] v, size_t numbits)` accepts arbitrary raw storage, validates only byte length and bit-count bounds, and then casts `v.ptr` to `size_t*`. If `v.ptr` is not aligned for `size_t`, the object is created in an invalid state and later methods perform undefined misaligned `size_t` reads and writes.

## Provenance
- Verified from the reported implementation and reproduced locally
- Scanner: https://swival.dev
- Patch file: `050-raw-void-constructor-permits-misaligned-size-t-access.patch`

## Preconditions
- Caller passes a misaligned `void[]` to `BitArray(void[], size_t)`

## Proof
The constructor at `std/bitmanip.d:671` stores `_ptr = cast(size_t*) v.ptr` after checking only storage length and `numbits` bounds.

Subsequent operations dereference `_ptr` as aligned `size_t*`, including:
- bit updates in `std/bitmanip.d:1268`
- bulk writes in `std/bitmanip.d:1281`
- population count reads in `std/bitmanip.d:1448`
- shift load/store paths in `std/bitmanip.d:2410`

A local PoC constructed a `BitArray` from a deliberately misaligned slice:
```d
auto ba = BitArray(cast(void[]) backing[1 .. 1 + size_t.sizeof], size_t.sizeof * 8);
ba[0] = true;
auto n = ba.count;
```

This succeeds on the test arm64 host, but inspection of a reduced example compiled with `ldc2` showed LLVM IR using aligned accesses (`load ... align 8`, `store ... align 8`) for the manufactured `size_t*`. Once the constructor accepts a misaligned pointer, later accesses violate the alignment contract.

## Why This Is A Real Bug
This is reachable through a public API with attacker-controlled raw storage. The constructor itself creates an invalid `size_t*`, and the rest of `BitArray` assumes native `size_t` alignment. On some targets this can trap; on others it can trigger sanitizer findings or optimizer-enabled miscompilation and silent corruption. The fact that one test system tolerated the access does not make the behavior defined.

## Fix Requirement
The constructor must reject misaligned raw pointers before casting to `size_t*`, or else copy into properly aligned backing storage before any typed access occurs.

## Patch Rationale
The patch adds an explicit alignment check in `BitArray.this(void[] v, size_t numbits)` and refuses inputs whose `v.ptr` is not aligned for `size_t`. This preserves the existing zero-copy behavior for valid callers, prevents construction of an invalid internal state at the API boundary, and blocks all later undefined typed accesses through `_ptr`.

## Residual Risk
None

## Patch
Patched in `050-raw-void-constructor-permits-misaligned-size-t-access.patch`.