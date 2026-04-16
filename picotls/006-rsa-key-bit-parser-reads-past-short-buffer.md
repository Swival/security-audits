# RSA key-bit parser reads past short buffer

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/mbedtls_sign.c:428`
- `lib/mbedtls_sign.c:551`

## Summary
`ptls_mbedtls_rsa_get_key_bits` reads ASN.1 header bytes from `key_value[x]` through `key_value[x + 3]` without first proving that those indices are in-bounds. A second unchecked read later dereferences `key_value[x]` after modulus-length parsing without verifying `x < key_length`. Reachable RSA PEM input can therefore trigger out-of-bounds reads on malformed or truncated DER before the function rejects the key.

## Provenance
- Verified from the supplied reproducer and call-path analysis.
- Reachability is via `ptls_mbedtls_load_private_key` -> `ptls_mbedtls_set_rsa_key_attributes` -> `ptls_mbedtls_rsa_get_key_bits`.
- External source: Swival Security Scanner, https://swival.dev

## Preconditions
- Caller passes RSA DER buffer shorter than 4 bytes past the current parser offset.
- Or caller passes malformed DER that advances parsing to the modulus-byte read with `x >= key_length`.

## Proof
- `ptls_mbedtls_load_private_key` forwards PEM-decoded RSA bytes to `ptls_mbedtls_set_rsa_key_attributes`, which invokes `ptls_mbedtls_rsa_get_key_bits`.
- `mbedtls_pem_read_buffer` accepts arbitrary non-empty base64-decoded payloads, so attacker-controlled short decoded buffers are practical parser input.
- In `ptls_mbedtls_rsa_get_key_bits`, the parser checks ASN.1 tags and length-form bytes by reading `key_value[x]`, `key_value[x + 1]`, `key_value[x + 2]`, and `key_value[x + 3]` before ensuring `x + 3 < key_length`.
- The reproducer used a 1-byte buffer `{0x02}` with the committed parser logic; ASan reported `stack-buffer-overflow` on the header read corresponding to the `x + 1`..`x + 3` access.
- A second unchecked dereference occurs after modulus-length parsing, where `key_value[x]` is read to inspect a leading zero byte without first checking `x < key_length`.

## Why This Is A Real Bug
The function processes reachable, externally supplied key material before cryptographic import. Its current rejection logic does not preserve the fundamental invariant that every indexed read must be preceded by a length check. On short DER input, the parser performs out-of-bounds memory reads before returning an error, which is a concrete memory-safety flaw and was confirmed under ASan.

## Fix Requirement
Add explicit bounds checks:
- verify `x + 3 < key_length` before reading the four-byte ASN.1 header window;
- verify `x < key_length` before reading the first modulus byte after parsing its length.

## Patch Rationale
The patch should fail closed at both read sites, returning parse failure before any dereference that depends on attacker-controlled structure length. This preserves existing behavior for valid RSA DER while restoring buffer-length invariants for malformed and truncated inputs.

## Residual Risk
None

## Patch
- Patch file: `006-rsa-key-bit-parser-reads-past-short-buffer.patch`
- The patch adds the missing pre-read bounds checks in `lib/mbedtls_sign.c` at the two reachable dereference sites, preventing the reproduced out-of-bounds reads while keeping valid DER parsing unchanged.