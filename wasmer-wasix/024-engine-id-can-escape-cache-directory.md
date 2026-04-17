# Engine ID Path Traversal in Filesystem Cache

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/module_cache/filesystem.rs:29`

## Summary
`FileSystemCache` derives on-disk cache paths from `engine.deterministic_id()` without validating or encoding that value first. Because the engine ID is joined directly into a filesystem path component, a caller that controls `deterministic_id()` can supply separators, `..`, or absolute-style values and cause cache reads and writes outside the configured cache directory.

## Provenance
- Report reproduced from the verified finding and local code inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker controls `Engine::deterministic_id()` contents
- The process uses `FileSystemCache` for `load()`, `contains()`, or `save()`

## Proof
- `load()`, `contains()`, and `save()` all pass `engine.deterministic_id()` into `path()` in `lib/wasix/src/runtime/module_cache/filesystem.rs`
- `path()` builds `cache_dir.join(format!("{deterministic_id}-v{artifact_version}"))` and then appends the module hash filename
- No validation or canonical containment check is applied before the resulting path is used by the filesystem backend helpers
- Reproduction establishes the precondition is satisfiable:
  - `Engine::deterministic_id()` forwards to the backend implementation at `lib/api/src/entities/engine/mod.rs:68`
  - The `sys` backend returns compiler-controlled data at `lib/compiler/src/engine/inner.rs:90`
  - The public `Compiler` trait exposes `fn deterministic_id(&self) -> String;` at `lib/compiler/src/compiler.rs:97`
  - Public engine construction accepts arbitrary compiler configuration at `lib/api/src/backend/sys/entities/engine.rs:127` and `lib/compiler/src/engine/inner.rs:58`
- Therefore an in-process caller can construct an engine whose deterministic ID is `../escaped` or an absolute path and trigger out-of-directory cache access through `tokio_save`, `tokio_load`, and `tokio_contains`

## Why This Is A Real Bug
This is not a theoretical misuse case. The reproducer shows that public APIs allow an in-process attacker to provide a custom compiler implementation and fully control `deterministic_id()`. Since that value is consumed as a path segment without sanitization, the cache layer can be redirected to attacker-chosen filesystem locations. That violates the cache directory boundary and enables unintended local file reads and writes under the process account.

## Fix Requirement
Reject unsafe engine IDs before path construction, or encode them into a path-safe representation so they cannot introduce traversal or absolute-path semantics.

## Patch Rationale
The patch should enforce that engine IDs used by `FileSystemCache` remain a single safe path component. Rejecting separators, parent-directory markers, and absolute-style inputs preserves the intended cache layout and closes traversal through all three affected operations (`load()`, `contains()`, and `save()`) at the shared path construction point.

## Residual Risk
None

## Patch
Saved as `024-engine-id-can-escape-cache-directory.patch`.