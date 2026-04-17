# Short metadata keys are accepted and stored

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `crypto/trust_token/trust_token.cc:426`

## Summary
`TRUST_TOKEN_ISSUER_set_metadata_key` reports `TRUST_TOKEN_R_INVALID_METADATA_KEY` when `len < 32` but continues execution, frees any prior key, stores the undersized caller input in issuer state, and returns success unless allocation fails. This violates the function's validation contract and leaves `ctx` configured with invalid metadata key material.

## Provenance
- Verified from the provided reproducer and source inspection in this tree
- Scanner provenance: https://swival.dev

## Preconditions
- Caller can invoke the metadata-key setter with a key shorter than 32 bytes

## Proof
At `crypto/trust_token/trust_token.cc:426`, the function checks for a short metadata key and raises `TRUST_TOKEN_R_INVALID_METADATA_KEY`, but does not return.
It then continues to:
- free the existing key at `crypto/trust_token/trust_token.cc:531`
- duplicate the short caller buffer into `ctx->metadata_key` at `crypto/trust_token/trust_token.cc:533`
- persist the short length in `ctx->metadata_key_len` at `crypto/trust_token/trust_token.cc:537`
- return success at `crypto/trust_token/trust_token.cc:538` unless allocation fails

Issuer state storage is confirmed by the `ctx` fields defined in `crypto/trust_token/internal.h:398`.

## Why This Is A Real Bug
The API performs input validation but fails open. A caller supplying a 1-byte key receives a successful result and mutates persistent issuer configuration to an invalid state. This is not merely an advisory error-path issue: the function both destroys any previously valid metadata key and stores the invalid replacement. That is a concrete contract violation and state corruption bug on a public API boundary.

## Fix Requirement
Return `0` immediately when `len < 32`, before freeing any existing key or storing new key material.

## Patch Rationale
The patch in `001-short-metadata-keys-are-accepted-and-stored.patch` makes the validation fail closed by returning immediately on undersized input. This preserves existing valid issuer state, prevents storage of invalid key material, and aligns the return value with the emitted error.

## Residual Risk
None

## Patch
```diff
diff --git a/crypto/trust_token/trust_token.cc b/crypto/trust_token/trust_token.cc
--- a/crypto/trust_token/trust_token.cc
+++ b/crypto/trust_token/trust_token.cc
@@ -426,6 +426,7 @@ int TRUST_TOKEN_ISSUER_set_metadata_key(TRUST_TOKEN_ISSUER *ctx,
   if (len < TRUST_TOKEN_NONCE_SIZE) {
     OPENSSL_PUT_ERROR(TRUST_TOKEN, TRUST_TOKEN_R_INVALID_METADATA_KEY);
+    return 0;
   }
 
   OPENSSL_free(ctx->metadata_key);
```