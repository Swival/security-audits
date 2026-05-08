# Unbounded RSA Attribute Length Allocation

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.bin/ssh/ssh-pkcs11.c:1094`

## Summary

`pkcs11_fetch_rsa_pubkey` trusted PKCS#11-reported RSA attribute lengths before allocating buffers. An attacker-controlled PKCS#11 provider or token could report a huge positive `CKA_MODULUS` or `CKA_PUBLIC_EXPONENT` length, causing `xcalloc(1, key_attr[i].ulValueLen)` to attempt an oversized allocation during SSH PKCS#11 key enumeration.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The user loads an attacker-controlled PKCS#11 provider or token.
- The provider exposes a `CKO_PUBLIC_KEY` object with key type `CKK_RSA`.
- The provider reports an enormous positive length for `CKA_MODULUS` or `CKA_PUBLIC_EXPONENT` during the first `C_GetAttributeValue` call.

## Proof

The reproduced path is:

- `pkcs11_add_provider` is reachable from SSH PKCS#11 provider loading paths such as `usr.bin/ssh/ssh.c:2352` and `usr.bin/ssh/ssh-pkcs11-helper.c:69`.
- `pkcs11_register_provider` initializes the token, opens a session, then calls `pkcs11_fetch_keys` at `usr.bin/ssh/ssh-pkcs11.c:1937`.
- `pkcs11_fetch_keys` enumerates `CKO_PUBLIC_KEY` objects and dispatches `CKK_RSA` objects to `pkcs11_fetch_rsa_pubkey` at `usr.bin/ssh/ssh-pkcs11.c:1572`.
- `pkcs11_fetch_rsa_pubkey` first calls `C_GetAttributeValue` to populate `key_attr[1].ulValueLen` and `key_attr[2].ulValueLen` for `CKA_MODULUS` and `CKA_PUBLIC_EXPONENT`.
- Before the patch, it rejected only zero lengths, then allocated each positive length with `xcalloc(1, key_attr[i].ulValueLen)`.
- A malicious provider can report a huge positive length, causing memory exhaustion before the second attribute read.
- Allocation failure is fatal through `usr.bin/ssh/xmalloc.c:49`, terminating SSH PKCS#11 enumeration.

## Why This Is A Real Bug

PKCS#11 attribute lengths are controlled by the provider/token backend and are not inherently trustworthy. The vulnerable code used those untrusted lengths directly as allocation sizes after checking only for zero. Because `xcalloc` is fatal on allocation failure, an oversized reported RSA modulus or exponent length can reliably terminate the process performing key enumeration.

## Fix Requirement

Cap RSA public key attribute lengths before allocation and reject oversized `CKA_MODULUS` or `CKA_PUBLIC_EXPONENT` values.

## Patch Rationale

The patch extends the existing RSA attribute-length validation to reject values larger than `SSHBUF_MAX_BIGNUM`. This places a bounded, key-material-appropriate limit on both RSA bignum inputs before any allocation occurs, preventing attacker-controlled oversized allocation attempts while preserving normal RSA key loading behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/ssh-pkcs11.c b/usr.bin/ssh/ssh-pkcs11.c
index e2bd8de..cb686f7 100644
--- a/usr.bin/ssh/ssh-pkcs11.c
+++ b/usr.bin/ssh/ssh-pkcs11.c
@@ -1012,7 +1012,9 @@ pkcs11_fetch_rsa_pubkey(struct pkcs11_provider *p, CK_ULONG slotidx,
 	 * XXX assumes CKA_ID is always first.
 	 */
 	if (key_attr[1].ulValueLen == 0 ||
-	    key_attr[2].ulValueLen == 0) {
+	    key_attr[2].ulValueLen == 0 ||
+	    key_attr[1].ulValueLen > SSHBUF_MAX_BIGNUM ||
+	    key_attr[2].ulValueLen > SSHBUF_MAX_BIGNUM) {
 		error("invalid attribute length");
 		return (NULL);
 	}
```