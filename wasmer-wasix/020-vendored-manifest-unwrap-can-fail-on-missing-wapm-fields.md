# Vendored manifest unwrap panics on partial `wapm` metadata

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/inputs.rs:204`

## Summary
A vendored dependency manifest routed through `UrlOrManifest::Manifest` can panic during specifier extraction when the `wapm` annotation exists but omits `name` or `version`. The code only checks that the annotation is present, then calls `name.unwrap()` and `version.unwrap().parse()?`, converting malformed untrusted manifest data into a process crash instead of a resolver error.

## Provenance
- Verified from the supplied finding and reproducer against project code paths using untrusted manifests
- Reference: https://swival.dev

## Preconditions
- A vendored dependency manifest is processed from `manifest.use_map`
- The vendored manifest is represented as `UrlOrManifest::Manifest`
- Its `wapm` annotation is present but missing `name` or `version`

## Proof
`PackageInfo::from_manifest()` passes vendored manifest entries into `url_or_manifest_to_specifier()`. In the `UrlOrManifest::Manifest` branch, the code checks `manifest.package_annotation("wapm")` and then dereferences optional fields with `unwrap()`. A manifest with partial `wapm` metadata therefore reaches a panic path during metadata extraction.

This is reachable from manifest-loading flows that consume local and remote package metadata, including:
- `lib/wasix/src/runtime/resolver/filesystem_source.rs:27`
- `lib/wasix/src/runtime/resolver/backend_source.rs:650`
- `lib/wasix/src/bin_factory/binary_package.rs:245`

The reproduced behavior is a denial of service during resolution/loading for crafted manifests.

## Why This Is A Real Bug
The input originates from manifests treated as data, not trusted internal state. The resolver already models parse and resolution failures as recoverable errors, so panicking on a missing optional field is incorrect behavior. Because the failing path is reachable from practical package ingestion flows, a malformed vendored manifest can crash resolution deterministically.

## Fix Requirement
Replace the unchecked `unwrap()` calls for `wapm.name` and `wapm.version` with validated extraction. If required fields are absent, either fall back to `origin` when available or return the existing resolver error instead of panicking.

## Patch Rationale
The patch changes specifier extraction to reject incomplete `wapm` annotations through normal error handling rather than assuming required fields are present. This preserves resolver availability, keeps malformed manifests in the existing error channel, and avoids changing behavior for valid vendored manifests.

## Residual Risk
None

## Patch
- `020-vendored-manifest-unwrap-can-fail-on-missing-wapm-fields.patch` hardens `lib/wasix/src/runtime/resolver/inputs.rs` by replacing unchecked `unwrap()` use on `wapm.name` and `wapm.version` with checked extraction and error propagation.