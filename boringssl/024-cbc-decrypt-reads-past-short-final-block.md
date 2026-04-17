# CBC decrypt rejects short final block

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `crypto/cipher/e_rc2.cc:231`

## Summary
`rc2_cbc_cipher_update` forwarded arbitrary nonzero lengths into `RC2_cbc_encrypt`. In decrypt mode, a length not divisible by 8 reaches the tail handling in `RC2_cbc_encrypt`, which still performs two 4-byte reads for the final fragment and can read past the provided buffer. The patch rejects non-block-multiple decrypt input before calling the low-level CBC routine.

## Provenance
- Verified from the supplied reproducer and code-path analysis
- Reference: https://swival.dev

## Preconditions
- RC2-CBC decrypt is invoked
- Input length is nonzero and not divisible by 8
- Caller reaches `rc2_cbc_cipher_update` directly, such as via `EVP_Cipher`

## Proof
- `rc2_cbc_cipher_update` passed `len` unchanged to `RC2_cbc_encrypt`.
- In decrypt mode, `RC2_cbc_encrypt` processes full 8-byte blocks, then enters a tail path when bytes remain.
- That tail path executes two `c2l(in, ...)` reads, totaling 8 bytes, before truncating output with `l2cn(..., l + 8)`.
- With a final fragment shorter than 8 bytes, those reads exceed the caller-provided input.
- The reproducer called `EVP_CipherInit_ex(ctx, EVP_rc2_cbc(), ..., enc=0)` and then `EVP_Cipher(ctx, out, in, 7)`.
- ASan reported a stack-buffer-overflow read on the path `EVP_Cipher -> rc2_cbc_cipher_update -> RC2_cbc_encrypt`.

## Why This Is A Real Bug
This is an actual memory-safety violation, not a theoretical contract mismatch. Even if the public API documents non-block-multiple input as undefined for block ciphers, the implementation exposes a reachable path where malformed input causes an out-of-bounds read from caller-controlled memory. The behavior is reproducible under ASan and occurs before any higher-level buffering or finalization can correct the length.

## Fix Requirement
Reject RC2-CBC decrypt input when `len` is not a multiple of the 8-byte block size before invoking `RC2_cbc_encrypt`.

## Patch Rationale
The patch adds a guard in `rc2_cbc_cipher_update` for decrypt mode and returns an error on non-block-aligned input. This is the narrowest safe fix because it blocks the invalid state at the provider boundary, preserves valid CBC behavior, and prevents the low-level routine from entering its unsafe short-tail path.

## Residual Risk
None

## Patch
```diff
*** Begin Patch
*** Add File: 024-cbc-decrypt-reads-past-short-final-block.patch
+diff --git a/crypto/cipher/e_rc2.cc b/crypto/cipher/e_rc2.cc
+index 1111111..2222222 100644
+--- a/crypto/cipher/e_rc2.cc
++++ b/crypto/cipher/e_rc2.cc
+@@ -228,6 +228,12 @@ static int rc2_cbc_cipher_update(EVP_CIPHER_CTX *ctx, uint8_t *out,
+   if (len == 0) {
+     return 1;
+   }
++
++  if (!ctx->encrypt && (len % RC2_BLOCK) != 0) {
++    OPENSSL_PUT_ERROR(CIPHER, CIPHER_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH);
++    return 0;
++  }
++
+   RC2_cbc_encrypt(in, out, len, &cctx->ks, ctx->iv, ctx->encrypt);
+   return 1;
+ }
*** End Patch
```