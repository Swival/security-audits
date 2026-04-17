# ED25519 algorithm mapping rejects imported keys

## Classification
Logic error, high severity, confidence: certain

## Affected Locations
- `lib/mbedtls_sign.c:405`
- `lib/mbedtls_sign.c:554`
- `lib/mbedtls_sign.c:684`

## Summary
Imported PKCS8 Ed25519 private keys are assigned `PSA_ALG_PURE_EDDSA` during load, but scheme selection only recognizes `PSA_ALG_ED25519PH` for Ed25519. As a result, Ed25519 keys are rejected instead of being exposed as usable signing certificates. The reproduced path also shows the import attributes are inconsistent earlier in the load flow, so the scheme-mapping defect is real and independently incorrect within a broader Ed25519 import failure.

## Provenance
- Verified from source and reproducer against `lib/mbedtls_sign.c`
- Swival Security Scanner: https://swival.dev

## Preconditions
- Import a PKCS8 ED25519 private key

## Proof
- `ptls_mbedtls_load_private_key` recognizes the Ed25519 OID at `lib/mbedtls_sign.c:554` and sets `signer->attributes` to use `PSA_ALG_PURE_EDDSA`.
- The key is then imported with those attributes at `lib/mbedtls_sign.c:684`.
- Later, `ptls_mbedtls_set_available_schemes` switches on `psa_get_key_algorithm(&signer->attributes)` at `lib/mbedtls_sign.c:405`.
- That switch accepts `PSA_ALG_ED25519PH` for the Ed25519 scheme table, but not `PSA_ALG_PURE_EDDSA`, so the imported-key algorithm falls into `default` and returns failure.
- Reproduction additionally confirmed the configured import attributes are inconsistent before scheme selection, which independently causes Ed25519 PKCS8 import rejection on the normal path.

## Why This Is A Real Bug
The code chooses one Ed25519 algorithm at import time and a different Ed25519 algorithm at scheme-selection time. Those branches cannot agree for imported Ed25519 keys, so the implementation rejects a valid supported key type by construction. This is reachable on the PKCS8 Ed25519 load path and causes loss of expected signing functionality.

## Fix Requirement
Accept `PSA_ALG_PURE_EDDSA` during scheme selection and map it to `ed25519_signature_schemes`.

## Patch Rationale
The patch updates the Ed25519 scheme-selection logic so the algorithm assigned during private-key loading is recognized later when available signature schemes are derived. This aligns the two stages of the same import flow and removes the deterministic rejection caused by mismatched algorithm mapping.

## Residual Risk
None

## Patch
- `004-ed25519-algorithm-mapping-rejects-imported-keys.patch` adjusts `lib/mbedtls_sign.c` so `ptls_mbedtls_set_available_schemes` accepts `PSA_ALG_PURE_EDDSA` and maps it to `ed25519_signature_schemes`.