# Keyed DSSE Verifier Ignores payloadType

## Classification

security_control_failure, high severity, confidence certain.

## Affected Locations

`crates/nono/src/trust/bundle.rs:261`

## Summary

The standalone keyed DSSE verifier accepted bundles whose `dsseEnvelope.payloadType` had been changed after signing. `verify_keyed_signature` parsed the DSSE payload and signature, but recomputed the DSSE pre-authentication encoding using the hardcoded in-toto payload type rather than the envelope's actual `payloadType`. This left `payloadType` outside the effective verification decision for keyed bundles.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A caller uses `verify_keyed_signature` for keyed Sigstore bundle verification.
- An attacker can supply or modify a keyed Sigstore bundle, such as through a malicious pack registry.

## Proof

The keyed verification path calls `DsseContents::from_bundle`, then verifies the ECDSA signature over DSSE PAE bytes.

Before the patch, `DsseContents` retained:

- raw bundle JSON
- decoded payload bytes
- parsed statement

It did not retain `dsseEnvelope.payloadType`.

At `crates/nono/src/trust/bundle.rs:261`, the verifier computed:

```rust
sigstore_verify::types::dsse::pae(
    crate::trust::dsse::IN_TOTO_PAYLOAD_TYPE,
    &contents.payload_bytes,
)
```

This means verification always used the hardcoded `application/vnd.in-toto+json` payload type, regardless of the value present in the bundle envelope.

A reproduced test confirmed the failure mode:

- Create a keyed signed bundle.
- Mutate only `dsseEnvelope.payloadType` to `text/plain`.
- Parse the mutated JSON as a `Bundle`.
- Call `verify_keyed_signature`.
- The verifier returned `Ok(())`.

The reproduced command was:

```sh
rustup run stable cargo test -p nono --test payload_type_poc --no-default-features
```

## Why This Is A Real Bug

DSSE signs `PAE(payloadType, payload)`, so `payloadType` is part of the authenticated data. A verifier that ignores the envelope's actual `payloadType` fails to enforce DSSE semantics.

The bug is exploitable because keyed bundle signing signs over `PAE(IN_TOTO_PAYLOAD_TYPE, payload)`. An attacker can mutate only the envelope `payloadType` after signing. Since the verifier recomputes PAE with the same hardcoded type instead of the mutated envelope value, the signature remains valid and the modified bundle is accepted.

This is a security-control failure in the keyed verification path: a signed DSSE envelope field is not actually verified.

## Fix Requirement

Extract `dsseEnvelope.payloadType` from the bundle and use that exact value when computing DSSE PAE for keyed signature verification. Missing `payloadType` must fail verification.

## Patch Rationale

The patch adds `payload_type: String` to `DsseContents`, extracts `dsseEnvelope.payloadType` during bundle parsing, returns a `TrustVerification` error if it is absent, and changes `verify_keyed_signature` to compute:

```rust
sigstore_verify::types::dsse::pae(&contents.payload_type, &contents.payload_bytes)
```

This aligns keyed verification with DSSE: the signature is verified over the payload type actually carried by the envelope plus the payload bytes.

With this change, a post-signing mutation from `application/vnd.in-toto+json` to `text/plain` changes the PAE input and causes ECDSA verification to fail.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/trust/bundle.rs b/crates/nono/src/trust/bundle.rs
index 47d7257..863d7b1 100644
--- a/crates/nono/src/trust/bundle.rs
+++ b/crates/nono/src/trust/bundle.rs
@@ -257,11 +257,9 @@ pub fn verify_keyed_signature(
     let contents = DsseContents::from_bundle(bundle, artifact_path)?;
     let sig_b64 = contents.signature_b64(artifact_path)?;
 
-    // Compute PAE over the payload
-    let pae_bytes = sigstore_verify::types::dsse::pae(
-        crate::trust::dsse::IN_TOTO_PAYLOAD_TYPE,
-        &contents.payload_bytes,
-    );
+    // Compute PAE over the envelope payload type and payload
+    let pae_bytes =
+        sigstore_verify::types::dsse::pae(&contents.payload_type, &contents.payload_bytes);
 
     // Decode signature
     let sig_bytes =
@@ -297,6 +295,8 @@ pub fn verify_keyed_signature(
 struct DsseContents {
     /// The raw bundle JSON as a `serde_json::Value` (for signature extraction)
     bundle_value: serde_json::Value,
+    /// DSSE envelope payload type
+    payload_type: String,
     /// Decoded DSSE payload bytes
     payload_bytes: Vec<u8>,
     /// The in-toto statement parsed from the DSSE payload
@@ -316,6 +316,13 @@ impl DsseContents {
                 reason: format!("invalid bundle JSON: {e}"),
             })?;
 
+        let payload_type = bundle_value["dsseEnvelope"]["payloadType"]
+            .as_str()
+            .ok_or_else(|| NonoError::TrustVerification {
+                path: context_path.display().to_string(),
+                reason: "missing DSSE payloadType".to_string(),
+            })?;
+
         let payload_b64 = bundle_value["dsseEnvelope"]["payload"]
             .as_str()
             .ok_or_else(|| NonoError::TrustVerification {
@@ -344,6 +351,7 @@ impl DsseContents {
 
         Ok(Self {
             bundle_value,
+            payload_type: payload_type.to_string(),
             payload_bytes: payload_decoded.as_bytes().to_vec(),
             statement,
         })
```