# AES-256-CTR misadvertises as AES128-CTR

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/mbedtls.c:196`

## Summary
`ptls_mbedtls_aes256ctr` is the AES-256-CTR algorithm descriptor, but its public `name` field is set to `"AES128-CTR"`. The same object carries `PTLS_AES256_KEY_SIZE` and `setup_aes256ctr`, so the implementation is 256-bit AES-CTR while advertising the 128-bit identifier. This creates a reachable algorithm-identity mismatch through exported globals and can mislead downstream code that matches, logs, or enforces policy by cipher name.

## Provenance
- Reproduced from the verified finding and confirmed in source
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Code inspects, logs, or matches cipher algorithm names exposed by the library

## Proof
At `lib/mbedtls.c:196`, `ptls_mbedtls_aes256ctr` is defined with:
- `key_size = PTLS_AES256_KEY_SIZE`
- `setup_crypto = setup_aes256ctr`
- `name = "AES128-CTR"`

This descriptor is also referenced as the CTR primitive for AES-256-GCM, so consumers reaching it through exported algorithm tables observe the wrong identifier. Reproduction confirmed that `gcm.ctr_cipher->name` also reports `"AES128-CTR"`.

Internal runtime behavior does not depend on this string for cipher operation: allocation and setup are driven by structural fields and callbacks, not `name`. The bug is therefore an externally visible identity/metadata violation, not proof of incorrect encryption.

## Why This Is A Real Bug
The descriptor simultaneously claims AES-256 semantics through its key size and setup callback while publishing the AES-128 name. That is a direct invariant break in a public algorithm object. Any caller relying on the advertised name for allowlists, deny-lists, telemetry, debugging, audits, or compatibility logic can make incorrect decisions about the active primitive. Reachability is direct because the affected object is exported and referenced by other exported algorithm tables.

## Fix Requirement
Change the `ptls_mbedtls_aes256ctr` descriptor name from `"AES128-CTR"` to `"AES256-CTR"`.

## Patch Rationale
The patch updates only the incorrect identifier string in `lib/mbedtls.c` so the public metadata matches the already-correct AES-256 key size and setup routine. This is the minimal fix that restores algorithm identity without altering cryptographic behavior or call paths.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/mbedtls.c b/lib/mbedtls.c
index 3f2f0ab..b1d4e6c 100644
--- a/lib/mbedtls.c
+++ b/lib/mbedtls.c
@@ -193,7 +193,7 @@ ptls_cipher_algorithm_t ptls_mbedtls_aes128ctr = {
 ptls_cipher_algorithm_t ptls_mbedtls_aes256ctr = {
     "mbedtls",
-    "AES128-CTR",
+    "AES256-CTR",
     PTLS_AES256_KEY_SIZE,
     PTLS_AES_BLOCK_SIZE,
     sizeof(struct aesctr_context_t),
```