# Cache path traversal in cache key handling

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/backend_source.rs:372`
- `lib/wasix/src/runtime/resolver/backend_source.rs:467`
- `lib/wasix/src/runtime/resolver/backend_source.rs:548`
- `lib/wasix/src/runtime/resolver/backend_source.rs:551`

## Summary
`Source::query()` forwards attacker-influenced package names into `FileSystemCache` path construction without rejecting traversal tokens. On Windows, `FileSystemCache::path()` only rewrites the native separator and preserves `/`, so names like `foo/../../outside` are joined as traversing components and can make cache reads and writes escape the intended package-specific cache path under `cache_dir`.

## Provenance
- Verified from the provided reproducer and affected source analysis in `lib/wasix/src/runtime/resolver/backend_source.rs`
- Scanner source: https://swival.dev

## Preconditions
- Local cache is enabled
- Attacker controls the queried package name string
- The application runs on Windows

## Proof
- `Source::query()` derives `package_name` from `PackageSource::Ident(PackageIdent::Named(n))` using `n.full_name()` and passes it into cache operations at `lib/wasix/src/runtime/resolver/backend_source.rs:372`.
- `lookup_cached_query()` uses the computed cache path for reads at `lib/wasix/src/runtime/resolver/backend_source.rs:467`.
- `update()` creates parent directories and persists cache files to the computed path at `lib/wasix/src/runtime/resolver/backend_source.rs:548` and `lib/wasix/src/runtime/resolver/backend_source.rs:551`.
- The reproducer showed a Windows path resolving to components including `ParentDir`, demonstrating that `foo/../../outside` survives sanitization and escapes the intended cache subpath.

## Why This Is A Real Bug
Cache path construction is security-sensitive because it controls filesystem read and write locations. Here, attacker input reaches `PathBuf::join()` with traversal segments intact on Windows, and the resulting path is used for both `fs::read` and persisted writes. That creates a real path traversal primitive outside the intended cache namespace when local caching is enabled.

## Fix Requirement
Reject package names containing any path separator or `..` before using them in cache path construction.

## Patch Rationale
The patch enforces validation on cache key inputs so package names containing `/`, `\`, or `..` are refused before any filesystem path is derived. This removes traversal semantics instead of trying to normalize them after joining, which is the safer boundary because both cache reads and writes share the same path builder.

## Residual Risk
None

## Patch
- `008-cache-path-traversal-through-unsanitized-package-names.patch` rejects unsafe package names before cache path construction in `lib/wasix/src/runtime/resolver/backend_source.rs`, preventing traversal-capable cache reads and writes on Windows.