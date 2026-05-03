# Encrypted PVK Key Length Checked After Eight-Byte Copy

## Classification

- Type: out-of-bounds read
- Severity: medium
- Confidence: certain

## Affected Locations

- `pem/pvkfmt.c:758`
- `pem/pvkfmt.c:765`
- `pem/pvkfmt.c:767`

## Summary

`b2i_PVK_bio()` can parse an attacker-supplied encrypted PVK whose `keylen` is less than 8. In the encrypted parsing path, `do_PVK_body()` copies eight bytes from the key buffer before checking that at least eight key bytes are present. For `keylen` values `0..7`, this reads past the allocated heap buffer before the malformed PVK is rejected.

## Provenance

- Source: Swival Security Scanner
- Scanner URL: https://swival.dev
- Finding was reproduced against the committed source and patched.

## Preconditions

- An application parses attacker-controlled PVK input with `b2i_PVK_bio()`.
- The PVK header has nonzero `saltlen`, causing the encrypted branch in `do_PVK_body()` to execute.
- The PVK header has `keylen < 8`.
- A password callback or default password callback returns a password.

## Proof

`do_PVK_header()` parses attacker-controlled `saltlen` and `keylen` and only rejects values above `65536`. It does not require encrypted PVK payloads to contain the eight-byte BLOBHEADER.

`b2i_PVK_bio()` then computes:

```c
buflen = keylen + saltlen;
buf = malloc(buflen);
BIO_read(in, buf, buflen);
```

This allocates and reads exactly the attacker-declared `saltlen + keylen` bytes.

In `do_PVK_body()`, when `saltlen` is nonzero, the parser derives the key, advances past the salt, and originally executed:

```c
memcpy(enctmp, p, 8);
p += 8;
if (keylen < 8) {
	PEMerror(PEM_R_PVK_TOO_SHORT);
	goto err;
}
```

With `keylen` in `0..7`, only `keylen` bytes remain after the salt. The `memcpy(enctmp, p, 8)` therefore reads `8 - keylen` bytes beyond the heap allocation. The rejection occurs only after the out-of-bounds read has already happened.

## Why This Is A Real Bug

The vulnerable copy operates on attacker-sized input that was allocated to exactly `saltlen + keylen` bytes. No earlier validation guarantees `keylen >= 8`. The encrypted branch reaches the copy whenever `saltlen` is nonzero and a password is obtained. Therefore a malformed encrypted PVK with `keylen < 8` causes a source-proven heap out-of-bounds read before error handling rejects the file.

## Fix Requirement

Reject encrypted PVK bodies with `keylen < 8` before copying the eight-byte BLOBHEADER or advancing the input pointer by eight bytes.

## Patch Rationale

The patch moves the existing `keylen < 8` validation before:

```c
memcpy(enctmp, p, 8);
p += 8;
```

This preserves the original error behavior for malformed short PVKs while ensuring the parser never reads beyond the bytes that `b2i_PVK_bio()` allocated and populated.

## Residual Risk

None

## Patch

```diff
diff --git a/pem/pvkfmt.c b/pem/pvkfmt.c
index 395fd9d..22edf89 100644
--- a/pem/pvkfmt.c
+++ b/pem/pvkfmt.c
@@ -761,13 +761,13 @@ do_PVK_body(const unsigned char **in, unsigned int saltlen,
 			goto err;
 		}
 		p += saltlen;
-		/* Copy BLOBHEADER across, decrypt rest */
-		memcpy(enctmp, p, 8);
-		p += 8;
 		if (keylen < 8) {
 			PEMerror(PEM_R_PVK_TOO_SHORT);
 			goto err;
 		}
+		/* Copy BLOBHEADER across, decrypt rest */
+		memcpy(enctmp, p, 8);
+		p += 8;
 		inlen = keylen - 8;
 		q = enctmp + 8;
 		if (!EVP_DecryptInit_ex(cctx, EVP_rc4(), NULL, keybuf, NULL))
```