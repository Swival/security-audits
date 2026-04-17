# Unchecked SHA sidecar overrides real package hash

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/resolver/inputs.rs:239`

## Summary
`PackageSummary::from_webc_file()` trusted `WebcHash::for_file()` to derive package identity and distribution metadata for local `.webc` files. `WebcHash::for_file()` accepted a sibling `.webc.sha256` file as authoritative whenever it contained 32 raw bytes, without hashing or comparing the actual `.webc` contents. A local attacker able to place that sidecar could therefore forge the package hash used as trusted metadata, and for unnamed packages influence the resolved package identity.

## Provenance
- Reproduced from the verified finding and source review
- Scanner: https://swival.dev

## Preconditions
- Attacker can place a sibling `.webc.sha256` file beside the target `.webc`

## Proof
- `PackageSummary::from_webc_file()` uses `WebcHash::for_file()` to populate `dist.webc_sha256` and derive the fallback package name/hash path for local packages in `lib/wasix/src/runtime/resolver/inputs.rs:239`.
- `WebcHash::for_file()` previously read the sibling `.webc.sha256` first and returned those raw 32 bytes as the package hash when present, without recomputing the `.webc` digest or checking equality.
- That forged hash then propagates into package resolution and cache identity. The reproduced trace shows consumers at `lib/wasix/src/runtime/resolver/in_memory_source.rs:73`, `lib/wasix/src/runtime/package_loader/builtin_loader.rs:425`, and `lib/wasix/src/runtime/package_loader/builtin_loader.rs:609`.
- The default local load path does not reject this mismatch up front because `BuiltinPackageLoader::new()` sets `HashIntegrityValidationMode::NoValidate` in `lib/wasix/src/runtime/package_loader/builtin_loader.rs:55`.
- Result: a writable sibling sidecar can override trusted integrity metadata for every local `from_webc_file()` load.

## Why This Is A Real Bug
The sidecar file crosses a trust boundary: it is separate attacker-controlled filesystem state, not authenticated package content. Using it as the canonical package hash allows integrity metadata and cache identity to diverge from the actual `.webc` bytes. That can misidentify unnamed packages, poison cache keys and filenames, and suppress expected content-addressed behavior on local loads. Because the default loader path does not validate the mismatch, exploitation is practical rather than theoretical.

## Fix Requirement
Always compute the hash from the `.webc` file itself. If a sibling `.webc.sha256` exists, treat it only as a cache hint and require it to match the computed digest before using or accepting it.

## Patch Rationale
The patch changes `WebcHash::for_file()` in `lib/wasix/src/runtime/resolver/inputs.rs` to always hash the target `.webc` and only consult the sidecar as a verified cache value. Sidecar data is accepted only when it exactly matches the freshly computed digest; otherwise the computed digest remains authoritative. This removes the trust-boundary violation while preserving sidecar utility as an optimization or consistency check.

## Residual Risk
None

## Patch
- `019-unchecked-sha-sidecar-overrides-real-package-hash.patch`