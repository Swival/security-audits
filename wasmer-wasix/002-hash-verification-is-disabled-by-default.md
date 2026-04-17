# Hash verification is disabled by default

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runtime/package_loader/builtin_loader.rs:45`

## Summary
`BuiltinPackageLoader::new()` defaults `hash_validation` to `NoValidate`, so remote package bytes are accepted, parsed, and cached without enforcing the advertised `dist.webc_sha256`. This allows attacker-altered content to be stored under the expected hash-derived cache path when the fetched bytes differ from the registry/backend-provided digest.

## Provenance
- Verified through local reproduction and patch validation
- Scanner provenance: https://swival.dev

## Preconditions
- Default `BuiltinPackageLoader` loads a remote package whose served bytes differ from the advertised `dist.webc_sha256`
- The advertised hash comes from an external trust source such as a registry or backend, not from hashing the just-downloaded bytes locally

## Proof
- `BuiltinPackageLoader::new()` initializes `hash_validation` as `HashValidationMode::NoValidate` in `lib/wasix/src/runtime/package_loader/builtin_loader.rs:45`
- `load()` reaches `download()`, which fetches `dist.webc`, decodes the response, and then calls `validate_hash()`
- In `NoValidate` mode, `validate_hash()` returns `Ok(())` without comparing the body against `dist.webc_sha256`
- `load()` then persists and parses the unverified bytes through the cache path derived from the expected hash
- Reproduction confirmed `loader.load(&summary).await.unwrap()` succeeds while unrelated bytes are served for a package declaring `[0xaa; 32]` as `webc_sha256`, and those bytes are written under the expected cache key in `lib/wasix/src/runtime/package_loader/builtin_loader.rs:840`, `lib/wasix/src/runtime/package_loader/builtin_loader.rs:854`, and `lib/wasix/src/runtime/package_loader/builtin_loader.rs:877`

## Why This Is A Real Bug
Integrity verification is the security boundary between trusted package metadata and untrusted package transport. With verification disabled by default, any actor able to cause byte substitution after metadata issuance can bypass that boundary. The loader then parses and caches attacker-controlled content as if it matched the trusted digest, defeating the purpose of the advertised hash and creating persistent integrity corruption.

## Fix Requirement
Default `BuiltinPackageLoader` to `HashValidationMode::FailOnHashMismatch` so downloaded package bytes must match `dist.webc_sha256` before parsing or caching.

## Patch Rationale
The patch changes the default constructor behavior in `lib/wasix/src/runtime/package_loader/builtin_loader.rs` to enforce hash validation on all default remote loads. This is the narrowest effective fix because it preserves the existing validation path and only changes the insecure default to the secure mode already supported by the implementation.

## Residual Risk
None

## Patch
- Patch file: `002-hash-verification-is-disabled-by-default.patch`
- Effect: changes the default `BuiltinPackageLoader` hash validation mode from `NoValidate` to `FailOnHashMismatch` in `lib/wasix/src/runtime/package_loader/builtin_loader.rs`