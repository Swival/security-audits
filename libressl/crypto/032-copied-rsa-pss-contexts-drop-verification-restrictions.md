# Copied RSA-PSS contexts drop verification restrictions

## Classification

Security control failure, high severity, confidence certain.

## Affected Locations

`rsa/rsa_pmeth.c:143`

## Summary

`pkey_rsa_copy()` failed to copy RSA-PSS salt-length enforcement fields from the source `EVP_PKEY_CTX` to the destination context. When an initialized verifier context for a restricted RSA-PSS key was duplicated, the copied context reverted to unrestricted defaults and could accept signatures whose PSS salt length violated the key parameters.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

RSA-PSS key has PSS restrictions and an initialized verifier context is copied.

## Proof

`pkey_pss_init()` enforces RSA-PSS key parameters by setting `rctx->min_saltlen` and `rctx->saltlen` from `rsa->pss`.

`pkey_rsa_copy()` calls `pkey_rsa_init(dst)`, which initializes the destination with:

- `saltlen = RSA_PSS_SALTLEN_AUTO`
- `min_saltlen = -1`

Before the patch, `pkey_rsa_copy()` copied `pad_mode`, `md`, and `mgf1md`, but omitted `saltlen` and `min_saltlen`.

The copied verifier context still reaches `pkey_rsa_verify()`, which passes `rctx->saltlen` to `RSA_verify_PKCS1_PSS_mgf1()`.

With `saltlen == RSA_PSS_SALTLEN_AUTO`, `rsa/rsa_pss.c` auto-recovers the salt length, and the exact salt-length check only applies when `sLen >= 0`. Therefore, a valid RSA-PSS signature using the same hash and MGF1 digest but a salt length below the restricted key minimum can be accepted by the copied verifier.

The reproduced failure is deterministic under the stated precondition: initialize verification for a restricted RSA-PSS key, duplicate the context, then verify a same-hash/MGF1 PSS signature whose salt length is below the key restriction.

## Why This Is A Real Bug

RSA-PSS key restrictions are part of the key’s verification policy. Copying an initialized `EVP_PKEY_CTX` must preserve that policy.

The original source context correctly rejects signatures with forbidden salt lengths because `pkey_pss_init()` sets `saltlen` and `min_saltlen`. The copied context silently drops those fields and verifies with `RSA_PSS_SALTLEN_AUTO`, causing the verifier to fail open for restricted RSA-PSS keys.

This is a security control bypass, not only a configuration mismatch, because the copied context accepts signatures that the restricted key requires it to reject.

## Fix Requirement

`pkey_rsa_copy()` must copy both RSA-PSS salt-length fields:

- `saltlen`
- `min_saltlen`

from the source RSA pkey context to the destination RSA pkey context.

## Patch Rationale

The patch copies `sctx->saltlen` and `sctx->min_saltlen` immediately after copying the other RSA padding and digest parameters.

This preserves the verification restrictions established by `pkey_pss_init()` when a context is duplicated. It also preserves unrestricted behavior for non-restricted contexts, because their copied values remain the initialized defaults.

## Residual Risk

None

## Patch

```diff
diff --git a/rsa/rsa_pmeth.c b/rsa/rsa_pmeth.c
index 0b7cd00..084829b 100644
--- a/rsa/rsa_pmeth.c
+++ b/rsa/rsa_pmeth.c
@@ -148,6 +148,8 @@ pkey_rsa_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src)
 	dctx->pad_mode = sctx->pad_mode;
 	dctx->md = sctx->md;
 	dctx->mgf1md = sctx->mgf1md;
+	dctx->saltlen = sctx->saltlen;
+	dctx->min_saltlen = sctx->min_saltlen;
 	if (sctx->oaep_label != NULL) {
 		free(dctx->oaep_label);
 		if ((dctx->oaep_label = calloc(1, sctx->oaep_label_len)) == NULL)
```