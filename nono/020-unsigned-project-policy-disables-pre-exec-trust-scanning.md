# Unsigned Project Policy Disables Pre-Exec Trust Scanning

## Classification

High severity security control failure.

## Affected Locations

`crates/nono-cli/src/trust_scan.rs:80`

## Summary

An unsigned project `trust-policy.json` could disable pre-exec trust scanning by setting `includes` to an empty list. `load_scan_policy` loaded the project policy before verifying its signature, then used fields from that unverified effective policy to decide whether signature verification was needed. Under the stated conditions, this made the scanner fail open and allowed execution to proceed without checking attacker-controlled unsigned instruction files.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- No user policy adding `includes`.
- No multi-subject `.nono-trust.bundle`.
- `trust_override` is `false`.
- Attacker can provide a project repository containing an unsigned root `trust-policy.json`.

## Proof

The vulnerable path is:

1. `load_scan_policy` discovers and loads root `trust-policy.json` before signature verification at `crates/nono-cli/src/trust_scan.rs:40`.
2. Signature verification is gated by `scan_has_signed_artifacts(root, &effective, skip_dirs)` at `crates/nono-cli/src/trust_scan.rs:80`.
3. If the attacker-controlled policy sets `includes: []` and no `.nono-trust.bundle` exists, `scan_has_signed_artifacts` returns `false` at `crates/nono-cli/src/trust_scan.rs:107`.
4. Because the gate is false, `verify_scan_policy_signatures` is not called.
5. The skipped verifier would have rejected the unsigned project policy because `verify_policy_signature` errors when the `.bundle` sidecar is missing at `crates/nono-cli/src/trust_scan.rs:161`.
6. The effective empty policy reaches `run_pre_exec_scan`, which returns an empty successful `ScanResult` at `crates/nono-cli/src/trust_scan.rs:332`.
7. `ScanResult::should_proceed()` allows execution when `blocked == 0` at `crates/nono-cli/src/trust_scan.rs:289`.

Result: unsigned instruction files in the project are ignored by the pre-exec trust scanner.

## Why This Is A Real Bug

The trust policy is itself security-critical input. Using an unverified project policy to decide whether that same policy needs verification lets an attacker suppress the verification path. This violates the intended fail-closed behavior because an unsigned policy that should be rejected can instead produce an empty scan result and permit execution.

## Fix Requirement

Discovered policy signatures must be verified before any fields from those policies are used to gate scanning or reduce scan scope, unless `trust_override` is explicitly enabled.

## Patch Rationale

The patch changes the verification condition so that when `trust_override` is false, policy signature verification runs whenever a project or user policy file was discovered, regardless of whether signed instruction artifacts are present.

This removes the attacker-controlled policy fields from the decision of whether to verify policy signatures. `scan_has_signed_artifacts` remains relevant only when no policy file was discovered.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/trust_scan.rs b/crates/nono-cli/src/trust_scan.rs
index 6df15a2..92f2af1 100644
--- a/crates/nono-cli/src/trust_scan.rs
+++ b/crates/nono-cli/src/trust_scan.rs
@@ -80,7 +80,11 @@ pub fn load_scan_policy(
         (None, None) => Ok(TrustPolicy::default()),
     }?;
 
-    if !trust_override && scan_has_signed_artifacts(root, &effective, skip_dirs)? {
+    if !trust_override
+        && (project_policy_path.is_some()
+            || user_policy_path.is_some()
+            || scan_has_signed_artifacts(root, &effective, skip_dirs)?)
+    {
         verify_scan_policy_signatures(
             project_policy_path.as_deref(),
             user_policy_path.map(PathBuf::as_path),
```