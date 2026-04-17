# RSA PKCS8 import slices wrong DER object

## Classification
- Type: logic error
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/mbedtls_sign.c:561`
- `lib/mbedtls_sign.c:673`
- `lib/mbedtls_sign.c:684`

## Summary
`ptls_mbedtls_load_private_key` unwraps PKCS#8 `BEGIN PRIVATE KEY` material with `test_parse_private_key_field`, yielding `key_index` and `key_length` for the inner private-key OCTET STRING payload. In the RSA branch, the code then switches back to the outer PKCS#8 buffer and length before deriving RSA attributes and calling `psa_import_key`. As a result, RSA-specific parsing receives a `PrivateKeyInfo` object instead of the required inner `RSAPrivateKey` DER object.

## Provenance
- Verified from the supplied reproducer and code-path analysis in `lib/mbedtls_sign.c`
- Scanner provenance: https://swival.dev
- Patch artifact: `005-rsa-pkcs8-import-slices-wrong-der-object.patch`

## Preconditions
- Load an RSA private key in PKCS#8 `-----BEGIN PRIVATE KEY-----` format

## Proof
- `test_parse_private_key_field` returns the offset and length of the inner OCTET STRING payload from PKCS#8 `PrivateKeyInfo`.
- For EC and Ed25519, the implementation continues operating on the unwrapped payload.
- For RSA at `lib/mbedtls_sign.c:561`, the implementation instead resets `key_length` to `pem.private_buflen` and later passes:
  - the outer buffer to `ptls_mbedtls_set_rsa_key_attributes` at `lib/mbedtls_sign.c:673`
  - `pem.private_buf + key_index` with the outer length to `psa_import_key` at `lib/mbedtls_sign.c:684`
- The reproducer confirms the DER object mismatch: the inner RSA `SEQUENCE` length resolves to 611 bytes, while the outer PKCS#8 object is 637 bytes.
- `ptls_mbedtls_rsa_get_key_bits`, used by `ptls_mbedtls_set_rsa_key_attributes`, expects an `RSAPrivateKey` layout beginning with `SEQUENCE, INTEGER version, INTEGER modulus`; PKCS#8 instead begins `SEQUENCE, INTEGER version, SEQUENCE algorithmIdentifier`, so key-bit extraction is also performed on the wrong object.

## Why This Is A Real Bug
PKCS#8 RSA handling is uniquely incorrect on the import path. The parser already identifies the correct inner `RSAPrivateKey` DER, but the RSA branch discards that slice and feeds the outer `PrivateKeyInfo` object into RSA-specific helpers and import APIs. This causes valid PKCS#8 RSA private keys to fail import or be mis-handled, breaking RSA signing setup when keys are provided in standard `BEGIN PRIVATE KEY` form.

## Fix Requirement
Use the parsed `key_index` and `key_length` payload as the RSA `RSAPrivateKey` DER object for both RSA attribute derivation and `psa_import_key`, rather than the outer PKCS#8 buffer and total length.

## Patch Rationale
The patch keeps the RSA PKCS#8 path aligned with the already-correct EC and Ed25519 handling:
- preserve the inner payload slice returned by `test_parse_private_key_field`
- pass that inner `RSAPrivateKey` DER to `ptls_mbedtls_set_rsa_key_attributes`
- import exactly that DER slice with `psa_import_key`

This corrects both RSA key-size derivation and the imported object without changing non-PKCS#8 behavior.

## Residual Risk
None

## Patch
`005-rsa-pkcs8-import-slices-wrong-der-object.patch`