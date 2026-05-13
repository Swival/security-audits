# NullableRef allows @safe dangling-pointer dereference

## Classification
- Type: resource lifecycle bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/typecons.d:2303`
- `std/typecons.d:5645`

## Summary
`NullableRef` accepts arbitrary external `T*` via its public constructor and `bind`, stores that pointer unchanged, and later dereferences it from `@safe` APIs after only a null check. A caller can therefore create a `NullableRef` to stack storage that expires before use, leading to a reachable use-after-scope read/write in safe code.

## Provenance
- Verified from the reported finding and local reproduction
- Reference: Swival Security Scanner, `https://swival.dev`
- Patch artifact: `013-nullableref-dereferences-external-pointer-without-lifetime-e.patch`

## Preconditions
- `NullableRef` binds a pointer that becomes invalid before later use

## Proof
- Input origin: `this(T* value)` and `bind(T* value)` accept arbitrary external pointers and assign them directly to `_value`.
- Dereference path: `get`, `opAssign`, and `toString` check only `_value !is null` before dereferencing `*_value` at `std/typecons.d:2303`.
- Safe-code trigger: compiling a function that returns `nullableRef(&arr[0])` where `arr` is a local static array succeeds under `@safe`; this was verified with `ldc2 -c -I. nullableref_staticarray_poc.d`.
- Runtime effect: after the callee returns and stack memory is reused, `nr.get` reads a corrupted value from the saved non-null address, demonstrating use-after-scope through `NullableRef`.

## Why This Is A Real Bug
The bug is not hypothetical memory-model abuse hidden behind `@system`: the API is publicly reachable from `@safe` code, the compiler accepts construction from stack-backed storage, and later safe methods dereference the stale pointer. The observed corrupted read after stack reuse confirms expired-lifetime access from a non-null `_value`, which is memory-unsafe behavior.

## Fix Requirement
Prevent `@safe` code from constructing `NullableRef` from raw external pointers. The minimum acceptable fix is to make the raw-pointer constructor and binder `@system`-only; a stronger design would replace them with lifetime-tracked or owned storage.

## Patch Rationale
The patch constrains the unsound entry points instead of trying to detect dangling pointers at dereference time, which is not reliable. Marking raw-pointer binding as `@system` removes the false `@safe` guarantee while preserving functionality for callers that explicitly opt into unsafe operations and lifetime management.

## Residual Risk
None

## Patch
The fix in `013-nullableref-dereferences-external-pointer-without-lifetime-e.patch` updates `NullableRef` so that raw-pointer construction/binding is no longer available as `@safe`, closing the reproduced use-after-scope path while leaving existing null-state behavior unchanged.