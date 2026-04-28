# Passphrase Bytes Left Uncleared

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`modules/ssl/ssl_engine_init.c:518`

## Summary

Encrypted private key passphrases queried during SSL startup were duplicated into temporary pool memory and tracked in `pphrases`. Cleanup later zeroed only the `char *` pointer array, not the passphrase buffers themselves. Plaintext passphrase bytes therefore remained in `ptemp` memory after the code logged that queried passphrases had been wiped.

## Provenance

Verified from the provided reproduced finding and patch material. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

Encrypted private key passphrase is queried during SSL startup.

## Proof

`pphrases` is created with element size `sizeof(char *)` in `ssl_init_Module`, so its elements are pointers to passphrase strings.

The passphrase flow is:

- `ssl_load_encrypted_pkey` queries passphrases during encrypted private key loading.
- The plaintext passphrase is duplicated with `apr_pstrdup(ppcb_arg->p, buf)` in `modules/ssl/ssl_engine_pphrase.c:606`.
- On successful key load, the duplicated passphrase pointer is pushed into `pphrases` in `modules/ssl/ssl_engine_pphrase.c:351`.
- Cleanup in `ssl_init_Module` previously called `memset(pphrases->elts, 0, pphrases->elt_size * pphrases->nelts)`.
- Because `pphrases->elts` contains `char *` entries, that `memset` cleared only pointer slots.
- `pphrases->nelts = 0` then dropped the only tracked references without clearing the pointed-to plaintext buffers.

Result: plaintext passphrase bytes remained in temporary pool memory until pool destruction, and could potentially persist in unzeroed heap/free-list memory afterward.

## Why This Is A Real Bug

The code explicitly intends to wipe sensitive passphrases and logs `Init: Wiped out the queried pass phrases from memory`, but the implementation only erased pointer values. The sensitive data is stored in separately allocated string buffers, so the old cleanup did not satisfy the intended security property. This is reachable with encrypted private key configurations that require passphrase querying during SSL startup.

## Fix Requirement

Before clearing the `pphrases` pointer array, iterate over each stored passphrase pointer and securely zero the referenced string buffer.

## Patch Rationale

The patch casts `pphrases->elts` to `char **`, walks each stored entry, and calls `OPENSSL_cleanse(elts[i], strlen(elts[i]))` for non-null passphrase buffers. This clears the actual plaintext passphrase bytes before the existing pointer-array `memset` and `nelts` reset remove references.

`OPENSSL_cleanse` is appropriate here because it is intended for sensitive memory erasure and resists compiler dead-store elimination better than a plain `memset`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_engine_init.c b/modules/ssl/ssl_engine_init.c
index 0fecdcf..d496686 100644
--- a/modules/ssl/ssl_engine_init.c
+++ b/modules/ssl/ssl_engine_init.c
@@ -515,6 +515,14 @@ apr_status_t ssl_init_Module(apr_pool_t *p, apr_pool_t *plog,
     }
 
     if (pphrases->nelts > 0) {
+        char **elts = (char **)pphrases->elts;
+        int i;
+
+        for (i = 0; i < pphrases->nelts; i++) {
+            if (elts[i]) {
+                OPENSSL_cleanse(elts[i], strlen(elts[i]));
+            }
+        }
         memset(pphrases->elts, 0, pphrases->elt_size * pphrases->nelts);
         pphrases->nelts = 0;
         ap_log_error(APLOG_MARK, APLOG_INFO, 0, s, APLOGNO(02560)
```