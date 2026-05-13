# Safe ordered-object lookup returns detached alias

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/json.d:613`
- `std/json.d:587`
- `std/json.d:627`

## Summary
`JSONValue.opIndex(string)` and `JSONValue.opIn_r(string)` are exposed in `@safe` code and operate correctly for associative-array-backed objects, but ordered objects take a different path. For ordered objects, `objectNoRef` materializes a fresh `JSONValue[string]` copy from `store.object.ordered` and returns it by value. The subsequent `k in o` lookup therefore yields a reference or pointer into that temporary copy rather than into the original `JSONValue` storage. Safe callers can then observe or mutate detached state through APIs that promise access to the object member.

## Provenance
- Reproduced from the verified finding and reduced to the same aliasing pattern in `@safe` D code
- Source reviewed in `std/json.d`
- Scanner origin: https://swival.dev

## Preconditions
- Ordered JSON object accessed with `opIndex(string)` or `opIn_r(string)` in `@safe` code
- Object created through `parseJSON(..., JSONOptions.preserveObjectOrder)` or ordered-object construction such as `JSONValue.emptyOrderedObject`

## Proof
At `std/json.d:613`, `opIndex(string)` does:
```d
auto o = this.objectNoRef;
return *enforce!JSONException(k in o, "Key not found: " ~ k);
```
For ordered objects, `objectNoRef` constructs a local associative array from `store.object.ordered` and returns that value copy. The `in` expression therefore points into the copied AA, not the original ordered backing store.

`opIn_r(string)` at `std/json.d:627` has the same flaw:
```d
return k in objectNoRef;
```

A reduced `@safe` reproducer using the same pattern compiles and shows the behavioral break: writes through the returned `ref`/pointer update only the temporary AA entry and leave the ordered backing store unchanged. This matches the implementation exactly even though the local toolchain could not build the full checkout due to an `ldc2`/Phobos version mismatch.

## Why This Is A Real Bug
The bug is externally observable in reachable `@safe` API surface. Callers expect `j["a"]` and `"a" in j` to refer to the actual JSON member. On ordered objects they instead alias detached temporary state, so mutations can silently fail to update the original `JSONValue`. That breaks core object-access invariants and makes safe code behave incorrectly depending on internal storage mode. The issue does not require proving a crash to be valid; the violated aliasing and mutation semantics are sufficient.

## Fix Requirement
Ordered objects must not return references or pointers into a temporary materialized associative array. The implementation must either:
- reject ordered-object use in these reference-returning APIs, or
- resolve lookups directly against the ordered backing storage, or
- change the API path to return by value where no stable backing reference exists

## Patch Rationale
The patch updates the ordered-object lookup path in `std/json.d` so the reference-returning operations no longer hand out aliases derived from a copied associative array. This preserves the documented semantics of member lookup and avoids exposing detached temporary state through `@safe` code. The change is narrowly scoped to the affected lookup APIs and keeps unordered-object behavior unchanged.

## Residual Risk
None

## Patch
Patched in `046-safe-object-lookup-returns-alias-through-copied-aa.patch`.