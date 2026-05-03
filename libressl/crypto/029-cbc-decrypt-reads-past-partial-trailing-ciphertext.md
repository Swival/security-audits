# CBC decrypt reads past partial trailing ciphertext

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`modes/cbc128.c:170`

## Summary

`CRYPTO_cbc128_decrypt` accepts a byte length but processes any trailing non-block-multiple ciphertext as though a full 16-byte CBC block is available. For a partial final block, it calls the block cipher on `in` and later updates `ivec` from bytes that are outside the caller-provided ciphertext buffer.

## Provenance

Verified and reproduced from a Swival Security Scanner finding: https://swival.dev

## Preconditions

An application passes attacker-controlled ciphertext and a non-block-multiple length to `CRYPTO_cbc128_decrypt`.

## Proof

After full 16-byte blocks are processed, any remaining `len` enters the trailing `while (len)` loop. That path immediately executes:

```c
(*block)(in, tmp.c, key);
```

`block128_f` consumes a 16-byte block, so a remaining length of 1..15 causes the block function to read past the provided ciphertext tail.

For `len < 16`, the same tail path also executes:

```c
for (; n < 16; ++n)
	ivec[n] = in[n];
```

This reads `in[n]` for missing ciphertext bytes through byte 15, producing an additional out-of-bounds read.

A remote peer that controls CBC ciphertext length can trigger this by sending ciphertext whose final block is shorter than 16 bytes to an application using this public CBC primitive.

## Why This Is A Real Bug

CBC decryption requires full ciphertext blocks. The function’s full-block loops correctly guard on `len >= 16`, but the final loop accepts any nonzero remainder. That contradicts the block cipher contract and permits reads beyond the input buffer. With exact-sized or guard-page-backed input, this can crash the process; otherwise, adjacent process memory is consumed by the block operation and IV update.

## Fix Requirement

Reject or ignore non-block-multiple trailing ciphertext before any block cipher call or IV update can read from a partial final block.

## Patch Rationale

The patch changes the trailing decrypt loop from `while (len)` to `while (len >= 16)`. This preserves processing of complete blocks while preventing the block cipher call and IV update from executing on a partial tail. As a result, no read occurs beyond the caller-provided ciphertext buffer for non-block-multiple input.

## Residual Risk

None

## Patch

```diff
diff --git a/modes/cbc128.c b/modes/cbc128.c
index 1b6858e..f71467c 100644
--- a/modes/cbc128.c
+++ b/modes/cbc128.c
@@ -185,7 +185,7 @@ CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
 			}
 		}
 	}
-	while (len) {
+	while (len >= 16) {
 		unsigned char c;
 		(*block)(in, tmp.c, key);
 		for (n = 0; n < 16 && n < len; ++n) {
```