# PWRI Unwrap Reads Past Short Stream-Cipher Encrypted Keys

## Classification

High severity out-of-bounds read.

## Affected Locations

`cms/cms_pwri.c:216`

## Summary

`kek_unwrap_key()` accepts attacker-controlled PWRI `encryptedKey` input whose length is shorter than the fixed RFC3211 check-byte fields it later reads. When the PWRI KEK cipher has a one-byte block size, encrypted key lengths 2 through 6 pass the existing size checks, but the function still reads `tmp[4]`, `tmp[5]`, and/or `tmp[6]` from a heap allocation of only `inlen` bytes.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Recipient decrypts an attacker-supplied CMS `EnvelopedData` message.
- The message uses PWRI password-recipient decryption.
- The PWRI KEK `AlgorithmIdentifier` selects a supported cipher with `block_size == 1`.
- The attacker supplies a short `encryptedKey` length between 2 and 6 bytes.

## Proof

`cms_RecipientInfo_pwri_crypt()` accepts the message-supplied PWRI `keyEncryptionAlgorithm`, unpacks its nested `AlgorithmIdentifier`, resolves the cipher with `EVP_get_cipherbyobj()`, and initializes `kekctx`.

On decrypt, it passes attacker-controlled `pwri->encryptedKey->data` and `pwri->encryptedKey->length` to `kek_unwrap_key()`.

For ciphers with `blocklen == 1`, such as AES-128-CFB128 or AES-128-OFB, `inlen` values 2 through 6 pass the original checks:

```c
if (inlen < 2 * blocklen)
	return 0;
if (inlen % blocklen)
	return 0;
```

`tmp = malloc(inlen)` then allocates only 2 to 6 bytes, but the RFC3211 check-byte expression unconditionally reads through `tmp[6]`:

```c
if (((tmp[1] ^ tmp[4]) & (tmp[2] ^ tmp[5]) & (tmp[3] ^ tmp[6])) != 0xff)
	goto err;
```

An ASan harness using the same unwrap body with AES-128-CFB128 and `inlen = 2` reports a heap-buffer-overflow at this check-byte expression.

## Why This Is A Real Bug

The existing validation only enforces two cipher blocks and block alignment. That is insufficient for RFC3211 unwrap parsing because the code unconditionally accesses bytes 0 through 6 regardless of cipher block size.

With one-byte-block ciphers, `2 * blocklen` is only 2, so malformed encrypted keys shorter than 7 bytes reach the fixed-index check-byte reads. The out-of-bounds access occurs before unwrap failure handling and is reachable from attacker-controlled CMS input during recipient decryption.

## Fix Requirement

Reject any PWRI encrypted key shorter than 7 bytes before decrypting or reading RFC3211 check bytes.

## Patch Rationale

The patch adds a minimum length check for the fixed RFC3211 fields:

```diff
-if (inlen < 2 * blocklen) {
+if (inlen < 7 || inlen < 2 * blocklen) {
```

This preserves the existing block-size and alignment requirements while ensuring `tmp[0]` through `tmp[6]` are always within the allocated `tmp` buffer before the check-byte expression executes.

## Residual Risk

None

## Patch

```diff
diff --git a/cms/cms_pwri.c b/cms/cms_pwri.c
index f64f4ab..29852af 100644
--- a/cms/cms_pwri.c
+++ b/cms/cms_pwri.c
@@ -232,7 +232,7 @@ kek_unwrap_key(unsigned char *out, size_t *outlen, const unsigned char *in,
 	unsigned char *tmp;
 	int outl, rv = 0;
 
-	if (inlen < 2 * blocklen) {
+	if (inlen < 7 || inlen < 2 * blocklen) {
 		/* too small */
 		return 0;
 	}
```