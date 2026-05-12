# Unsigned Project Policy Can Define Trusted Publishers

## Classification

High-severity policy bypass.

## Affected Locations

`crates/nono-cli/src/trust_cmd.rs:1056`

## Summary

`nono trust verify` accepted an unsigned repository-local `trust-policy.json` as authoritative when no user-level policy existed. A malicious repository author could add attacker-controlled publishers and inline public keys to that policy, sign instruction files with the matching private key, and have verification succeed.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The verifier runs `nono trust verify` inside an attacker-controlled repository.
- No user-level trust policy exists for the verifier.
- The repository contains an unsigned `trust-policy.json`.
- The repository policy lists an attacker-controlled publisher key.

## Proof

The vulnerable flow auto-discovers `trust-policy.json` in the current working directory, calls `verify_policy_if_exists`, then loads the policy with `trust::load_policy_from_file`.

Before the patch, `verify_policy_if_exists` returned `Ok(())` when the `.bundle` sidecar was absent, only printing a warning. If no user policy existed, `load_trust_policy` returned the unsigned project policy directly.

Runtime reproduction confirmed the bypass:

```text
Warning: trust policy .../repo/trust-policy.json has no .bundle sidecar (unsigned).
Warning: project-level trust-policy.json found but no user-level policy exists.
VERIFIED .../repo/INSTRUCTIONS.md
Signer: file://.../attacker.key (keyed)

Verified 1 file(s) successfully.
```

The verifier exited with status `0`.

## Why This Is A Real Bug

The trust policy defines which publishers are trusted. Allowing an unsigned repository-local policy to supply trusted publishers lets the repository author define the trust root for their own malicious content.

For keyed signatures, verification uses the inline `public_key` from the matching publisher before falling back to keystore lookup. Therefore, the attacker can include their own publisher public key in `trust-policy.json`, sign `INSTRUCTIONS.md`, and satisfy `verify_single_file`.

This defeats the expected integrity property of `trust verify`: instruction files should only verify when signed by publishers trusted independently of the untrusted repository contents.

## Fix Requirement

Project policies must not be honored unless their signature is verified. An unsigned project policy must fail closed, especially when no trusted user-level policy exists.

## Patch Rationale

The patch changes `verify_policy_if_exists` from permissive to mandatory verification:

```diff
-/// Verify the trust policy signature if a `.bundle` sidecar exists.
+/// Verify the trust policy signature before loading it.
...
-    let bundle_path = nono::trust::bundle_path_for(policy_path);
-    if !bundle_path.exists() {
-        eprintln!(...);
-        return Ok(());
-    }
     crate::trust_scan::verify_policy_signature(policy_path)
```

By always delegating to `crate::trust_scan::verify_policy_signature(policy_path)`, missing or invalid policy bundles become verification failures instead of warnings. This prevents unsigned project policies from contributing trusted publishers.

## Residual Risk

None

## Patch

`012-unsigned-project-policy-can-define-trusted-publishers.patch` removes the unsigned-policy allow path in `crates/nono-cli/src/trust_cmd.rs` and requires trust policy signature verification before loading.