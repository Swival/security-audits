# Missing env secret becomes empty bytes

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/config/secret_store.rs:142`

## Summary
A secret item configured with `env` silently resolves to empty bytes when the referenced environment variable is unset or contains invalid Unicode. The code calls `std::env::var(var)` and collapses any error with `unwrap_or_else(|_| String::new())`, then stores the resulting `Vec::new()` as the secret instead of rejecting configuration.

## Provenance
- Verified from source review and reproducer analysis
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Secret configuration uses `env`
- The referenced environment variable is unset or contains invalid Unicode

## Proof
At `src/config/secret_store.rs:142`, config-controlled `env` input reaches `std::env::var(var)`. Any `Err` is converted into `String::new()` by `unwrap_or_else(|_| String::new())`, and `into_bytes()` then produces an empty byte vector.

That empty value is accepted by `SecretStore::add_secret` in `src/secret_store.rs:40`, exposed by `Secret::plaintext` in `src/secret_store.rs:51`, and returned directly by retrieval paths in `src/wiggle_abi/secret_store_impl.rs:91` and `src/component/compute/secret_store.rs:58`. As a result, a guest can open the secret successfully and receive empty plaintext rather than a configuration error.

The condition is reachable whenever a parsed secret item uses only `env = "MISSING_VAR"`.

## Why This Is A Real Bug
This behavior converts an invalid secret source into a valid stored secret with different semantics. Operators expect a missing or unreadable environment-backed secret to fail configuration, not degrade into an empty secret value. Because empty secrets are accepted throughout storage and retrieval, the failure is silent and can cause authentication or cryptographic misconfiguration at runtime.

## Fix Requirement
Reject `env`-backed secrets when `std::env::var` fails. Propagate the environment lookup error as invalid secret-store configuration and never substitute empty bytes.

## Patch Rationale
The patch should replace the fallback-to-empty behavior in `src/config/secret_store.rs` with explicit error propagation so configuration loading fails for unset or invalid-Unicode environment variables. This matches operator intent, preserves error causality, and prevents invalid secrets from entering the store.

## Residual Risk
None

## Patch
- `030-missing-env-secret-becomes-empty-bytes.patch`