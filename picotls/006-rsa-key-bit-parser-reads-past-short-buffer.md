# RSA key-bit parser overreads short DER input

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/mbedtls_sign.c:428`
- `lib/mbedtls_sign.c:551`

## Summary
`ptls_mbedtls_rsa_get_key_bits` reads RSA DER header bytes without first proving enough input remains. On short or malformed PEM-decoded RSA input, reachable through `ptls_mbedtls_load_private_key`, the function can read past `key_value` before returning an error.

## Provenance
- Reported from reproduced analysis and patch validation
- External scanner reference: https://swival.dev

## Preconditions
- Caller passes RSA DER input with fewer than 4 bytes remaining at the current parse offset
- Or caller advances to modulus parsing with `x >= key_length`

## Proof
- `ptls_mbedtls_load_private_key` forwards PEM-decoded RSA bytes into `ptls_mbedtls_set_rsa_key_attributes`, which invokes `ptls_mbedtls_rsa_get_key_bits`.
- `mbedtls_pem_read_buffer` accepts arbitrary non-empty base64-decoded payloads, so attacker-controlled malformed RSA PEM can reach this parser.
- In `lib/mbedtls_sign.c:428`, the function evaluates `key_value[x]` through `key_value[x + 3]` during DER header checks without first enforcing `x + 3 < key_length`.
- In `lib/mbedtls_sign.c:551`, after modulus-length parsing, it reads `key_value[x]` without first enforcing `x < key_length`.
- Reproduction used an ASan harness with the in-tree parsing logic and a 1-byte buffer `{0x02}`; ASan reported `stack-buffer-overflow` on the header read path.

## Why This Is A Real Bug
The vulnerable reads occur before the parser rejects malformed input, so invalid key material can trigger memory-safety violations instead of clean failure. The input path is reachable from PEM parsing of private keys, and upstream PEM decoding does not enforce DER structural minimums that would prevent these short buffers from arriving here.

## Fix Requirement
Add explicit bounds checks before:
- reading the 4-byte DER header window
- reading the first modulus byte after modulus-length parsing

## Patch Rationale
The patch adds length guards for both read sites:
- reject when fewer than 4 bytes remain before inspecting `key_value[x]..key_value[x + 3]`
- reject when `x >= key_length` before reading the modulus byte

This preserves existing parsing behavior for valid DER while converting malformed short inputs into normal parse failure.

## Residual Risk
None

## Patch
- Patch file: `006-rsa-key-bit-parser-reads-past-short-buffer.patch`
- Patched file: `lib/mbedtls_sign.c`