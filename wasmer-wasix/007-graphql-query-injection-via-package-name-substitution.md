# GraphQL query injection via package name substitution

## Classification
- Type: vulnerability
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/backend_source.rs:73`

## Summary
`Source::query()` forwards attacker-controlled package names into `query_graphql_named()`, which constructs a GraphQL document by raw string substitution with `WASMER_WEBC_QUERY_ALL.replace("$NAME", package_name)`. Because `$NAME` is embedded inside a quoted GraphQL string literal, crafted input containing `"` and GraphQL syntax escapes the intended value and injects additional fields into the operation.

## Provenance
- Verified finding reproduced from scanner output and manual validation
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Attacker controls queried named package string

## Proof
`Source::query()` reads `package_name` from `PackageSource::Ident(PackageIdent::Named(n))` via `n.full_name()`, then passes it to `query_graphql_named()`. That function builds the request body with `WASMER_WEBC_QUERY_ALL.replace("$NAME", package_name)` before JSON serialization.

A crafted package name such as:
```text
") { piritaDownloadUrl piritaSha256Hash webcManifest } v3: distribution(version: V3) { piritaDownloadUrl piritaSha256Hash webcManifest } } } injected:getPackage(name: "wasmer/python
```

produces a valid GraphQL document with an extra top-level field:
```graphql
injected:getPackage(name: "wasmer/python")
```

The modified request was sent to the real registry endpoint with `curl`, and the response contained `data.getPackage`, `data.info`, and attacker-added `data.injected`, confirming execution of the injected field set.

## Why This Is A Real Bug
This is not a harmless parse failure. The injected operation is accepted by the registry and executed under the caller's authenticated context. Although local deserialization only consumes `getPackage` and `info` in `lib/wasix/src/runtime/resolver/backend_source.rs:671`, the vulnerability still allows attacker input to alter server-side work, trigger unintended lookups, and expand the effective query sent to the registry.

## Fix Requirement
Stop interpolating package names into GraphQL source text. Use GraphQL variables for the package name, or otherwise apply correct GraphQL string-literal escaping before request construction.

## Patch Rationale
The patch replaces raw `$NAME` document substitution with a safe parameterization approach so attacker-controlled package names are transmitted as data rather than syntax. This preserves the intended query shape and prevents quote-breaking or field injection while keeping package lookup behavior unchanged for valid names.

## Residual Risk
None

## Patch
- Patched in `007-graphql-query-injection-via-package-name-substitution.patch`
- The fix ensures package names are no longer inserted directly into the GraphQL document and cannot modify the operation structure.