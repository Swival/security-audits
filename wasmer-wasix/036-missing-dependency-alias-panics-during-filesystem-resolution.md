# Missing dependency alias panics during filesystem resolution

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/resolve.rs:298`

## Summary
`resolve_package()` trusts `FileSystemMapping.dependency_name` and unwraps the result of an alias lookup in the dependency graph. If package metadata names a filesystem dependency alias that is not declared, resolution panics instead of returning a typed `ResolveError`, allowing malformed WEBC metadata to trigger resolver-level denial of service.

## Provenance
- Verified from supplied reproducer and code inspection
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Package filesystem mapping names a non-existent dependency alias

## Proof
At `lib/wasix/src/runtime/resolver/resolve.rs:298`, the resolver handles `fs_mapping.dependency_name` by scanning outgoing dependency edges for a matching alias:
```rust
let dependency = graph
    .edges_directed(current, petgraph::Direction::Outgoing)
    .find(|edge| edge.weight().alias == *name)
    .unwrap()
    .target();
```
If no edge has the requested alias, `find()` returns `None` and `unwrap()` panics.

Reachability is direct:
- `resolve()` invokes dependency graph construction and then `resolve_package(...)` on the resulting graph at `lib/wasix/src/runtime/resolver/resolve.rs:29`.
- Existing package ingestion paths do not guarantee this field is valid for all loaded manifests; the reproduced case is a package whose declared dependency alias is `dep` while a filesystem mapping references `missing`.

Result: dependency resolution can succeed, then filesystem resolution panics on malformed metadata rather than emitting a recoverable resolver error.

## Why This Is A Real Bug
This is externally influenced metadata consumed by library code. A malformed or crafted WEBC manifest can deterministically crash the resolver on a normal code path. That is a denial-of-service condition and violates expected resolver semantics, which otherwise use `ResolveError` for invalid package state.

## Fix Requirement
Replace the `unwrap()` on filesystem dependency alias lookup with an explicit `ResolveError` for unknown aliases, preserving normal error propagation.

## Patch Rationale
The patch converts the unchecked alias lookup into a fallible branch that returns a typed resolver error when the alias is missing. This preserves behavior for valid manifests, eliminates the panic, and aligns filesystem dependency resolution with the resolver's existing error-handling model.

## Residual Risk
None

## Patch
Attached patch: `036-missing-dependency-alias-panics-during-filesystem-resolution.patch`