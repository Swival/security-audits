# Seal/Open Length Limit Mismatch In AES-EAX

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `crypto/cipher/e_aeseax.cc:201`

## Summary
- `aead_aes_eax_sealv` accepted total plaintext lengths larger than the AES-EAX maximum enforced by the decrypt path.
- `aead_aes_eax_openv_detached` already rejected inputs when total ciphertext length exceeded `(1<<36) + AES_BLOCK_SIZE`, so `sealv` could generate outputs that the paired open path would always reject.
- This caused deterministic self-incompatibility and denial of service for oversized AES-EAX messages.

## Provenance
- Verified from the supplied reproducer and code inspection.
- Public scanner reference: https://swival.dev

## Preconditions
- A caller encrypts more than `2^36 + 16` bytes with AES-EAX.
- The caller later attempts to decrypt the resulting ciphertext through the corresponding AES-EAX open path.

## Proof
- In `aead_aes_eax_sealv`, nonce and tag-size validation occurred before encryption and OMAC processing, but there was no total-input-length bound.
- The seal path therefore proceeded into CTR encryption and authentication for arbitrarily large aggregate `iovecs`.
- In `aead_aes_eax_openv_detached`, `bssl::iovec::TotalLength(iovecs)` was computed and compared against `(1<<36) + AES_BLOCK_SIZE`, returning `BAD_DECRYPT` when exceeded.
- The CTR backend does not prevent sealing near this boundary: `CRYPTO_ctr128_encrypt_ctr32` documents counter increment and wrap behavior, so encryption itself does not fail first.
- As a result, any ciphertext emitted by `sealv` above that limit is guaranteed to be rejected by the paired decrypt path.

## Why This Is A Real Bug
- The defect is directly reachable through the public AEAD API surface on 64-bit builds using multiple `iovecs`.
- It violates a basic encrypt/decrypt contract: the implementation can produce ciphertext that its own decryptor deterministically refuses.
- The failure mode is not theoretical; it is a reproducible interoperability break and denial of service for oversized messages.

## Fix Requirement
- Enforce the same aggregate length bound in `aead_aes_eax_sealv` that `aead_aes_eax_openv_detached` already applies.
- Reject oversized inputs before CTR encryption or OMAC computation.

## Patch Rationale
- The patch adds the missing total-length check to the seal path in `crypto/cipher/e_aeseax.cc`.
- This aligns encryption-time validation with existing decryption-time validation, restoring internal consistency without changing valid-message behavior.
- Rejecting early prevents generation of ciphertexts that are known to be undecryptable by the same implementation.

## Residual Risk
- None

## Patch
```diff
diff --git a/crypto/cipher/e_aeseax.cc b/crypto/cipher/e_aeseax.cc
index 0000000..0000000 100644
--- a/crypto/cipher/e_aeseax.cc
+++ b/crypto/cipher/e_aeseax.cc
@@ -201,6 +201,13 @@ static int aead_aes_eax_sealv(const EVP_AEAD_CTX *ctx, uint8_t *out,
   if (max_out_tag_len < eax_ctx->tag_len) {
     OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_BUFFER_TOO_SMALL);
     return 0;
   }
+
+  const uint64_t in_len_64 = bssl::iovec::TotalLength(in);
+  if (in_len_64 > (UINT64_C(1) << 36) + AES_BLOCK_SIZE) {
+    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_TOO_LARGE);
+    return 0;
+  }
+
   if (!eax_omac(ctx, nonce_omac, 0, nonce, nonce_len) ||
       !eax_omac(ctx, ad_omac, 1, ad, ad_len)) {
     return 0;
```