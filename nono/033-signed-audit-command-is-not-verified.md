# Signed audit command is not verified

## Classification

Security control failure, high severity.

Confidence: certain.

## Affected Locations

`crates/nono-cli/src/audit_attestation.rs:341`

## Summary

`verify_audit_attestation` verifies the signed attestation bundle, signer identity, public key, Merkle root, and `session_id`, but it does not verify the signed predicate `command` against `metadata.command`.

`write_audit_attestation` signs a scrubbed copy of `metadata.command` into the predicate. The verifier is expected to bind the saved session command to the signed attestation. Without that comparison, an attacker who can modify a saved session metadata file can change the displayed or reported command while preserving the valid signed bundle and integrity root.

## Provenance

Detected by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Attacker controls saved session metadata on disk.
- Attacker preserves a valid `audit-attestation.bundle`.
- Attacker preserves the original `metadata.session_id`.
- Attacker preserves the original `metadata.audit_integrity.merkle_root`.
- Attacker preserves the original `metadata.audit_attestation` summary.

## Proof

`write_audit_attestation` signs an `AuditAttestationPredicate` containing:

- `session_id`
- `started`
- `ended`
- `command` (scrubbed via `scrub_argv_with_policy`)
- `redaction_policy` (diff from secure default)
- audit log integrity fields
- signer metadata

During verification, `verify_audit_attestation` checks:

- predicate type
- signer identity
- attested public key encoding and key id
- keyed signature
- bundle digest against `metadata.audit_integrity.merkle_root`
- signed `predicate.session_id` against `metadata.session_id`

After `extract_statement`, the verifier only reads `predicate["session_id"]`. It never reads or compares `predicate["command"]`.

A practical trigger is:

1. Start with a valid signed audit session.
2. Modify only saved `SessionMetadata.command`.
3. Preserve `metadata.session_id`, `metadata.audit_integrity.merkle_root`, `metadata.audit_attestation`, and `audit-attestation.bundle`.
4. Run the audit attestation verifier.

The verifier still reports `signature_verified: true`, `merkle_root_matches: true`, `session_id_matches: true`, and `verification_error: None`. The forged command is accepted by this attestation verification control.

## Why This Is A Real Bug

The attestation writer includes the scrubbed command in the signed predicate, so the recorded command is part of the intended security boundary. The verifier fails open because it accepts metadata whose command no longer matches the signed predicate. This breaks the binding between the attested audit session and the command reported in saved session metadata.

The separate ledger verifier may detect command tampering in a broader CLI flow when the ledger is present and intact, but that does not make `verify_audit_attestation` reject the forged command.

## Fix Requirement

During attestation verification, parse the signed predicate `command` and compare it to the scrubbed form of `metadata.command`. Verification must fail if:

- the predicate does not contain `command`
- `command` is not a JSON array of strings
- the signed command differs from the scrubbed `metadata.command`

The comparison must be made against the scrubbed form because the predicate stores `scrub_argv_with_policy(metadata.command, redaction_policy)`. In production, `metadata.command` is itself stored already-scrubbed with the same policy, and `scrub_argv_with_policy` is idempotent on its own output, so re-scrubbing at verification time is safe and is also defensive against metadata files that recorded an unscrubbed command.

## Patch Rationale

The patch extracts `predicate["command"]` as `Vec<String>`. If the field is missing or malformed, verification fails with a clear error. It then scrubs `metadata.command` with `ScrubPolicy::secure_default()` and compares to the signed command. A mismatch returns `attestation_failure` with a descriptive message.

Using `secure_default` on the verifier side is robust:

- A signer that used the default policy produces identical output.
- A signer that used a stricter custom policy produces output that is already redacted at every default-sensitive key. Re-scrubbing already-redacted placeholders is a no-op, so the comparison still holds.
- A tampered metadata file containing raw secrets will be redacted by the verifier before comparison, so swaps of the surrounding command structure are detected.

This preserves the existing non-fatal verification behavior while ensuring the success result is only returned when the saved command is bound to the signed predicate.

## Residual Risk

An attacker who substitutes a different command whose scrubbed form is byte-identical to the signed scrubbed command would still pass verification. This is an inherent limitation of binding a redacted command rather than a raw command, and is consistent with the existing design choice to keep secrets out of attestation bundles.

## Patch

```diff
diff --git a/crates/nono-cli/src/audit_attestation.rs b/crates/nono-cli/src/audit_attestation.rs
index d109f61..5c280b7 100644
--- a/crates/nono-cli/src/audit_attestation.rs
+++ b/crates/nono-cli/src/audit_attestation.rs
@@ -335,6 +335,25 @@ pub(crate) fn verify_audit_attestation(
             ),
         ));
     }
+    let Some(statement_command) = statement
+        .predicate
+        .get("command")
+        .and_then(|value| serde_json::from_value::<Vec<String>>(value.clone()).ok())
+    else {
+        return Ok(attestation_failure(
+            summary,
+            expected_public_key_file.map(|_| true),
+            "audit attestation predicate missing command".to_string(),
+        ));
+    };
+    let scrubbed_metadata_command =
+        nono::scrub_argv_with_policy(&metadata.command, &nono::ScrubPolicy::secure_default());
+    if statement_command != scrubbed_metadata_command {
+        return Ok(attestation_failure(
+            summary,
+            expected_public_key_file.map(|_| true),
+            "audit attestation command does not match session metadata".to_string(),
+        ));
+    }
 
     Ok(AuditAttestationVerificationResult {
         present: true,
```
