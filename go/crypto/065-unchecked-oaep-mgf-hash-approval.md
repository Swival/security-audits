# Unchecked OAEP MGF Hash Approval

## Classification
Validation gap, medium severity. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140/rsa/pkcs1v22.go:429`

## Summary
`DecryptOAEP` validates the primary OAEP hash but does not validate the caller-controlled MGF1 hash before using it for OAEP unmasking. A successful RSA-OAEP decrypt can therefore be recorded as approved even when `MGFHash` is not an approved FIPS hash.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
- Caller supplies `DecryptOAEP` with an otherwise valid OAEP ciphertext.
- Caller selects an approved OAEP hash, such as SHA-256.
- Caller selects an unapproved `mgfHash`, such as SHA-1.
- Execution is not blocked by a stricter external FIPS-only policy before this code path.

## Proof
- `mgfHash` is caller-controlled through OAEP options.
- `DecryptOAEP` calls approval tracking for the main OAEP hash only.
- `mgfHash` is passed to `mgf1XOR` for seed and DB unmasking without a prior approval check.
- The repository tests already exercise OAEP with `Hash: crypto.SHA256` and `MGFHash: crypto.SHA1` in `src/crypto/rsa/rsa_test.go:999`.
- If `checkApprovedHash(mgfHash)` were called, non-SHA2/SHA3 hashes would call `fips140.RecordNonApproved()` via `src/crypto/internal/fips140/rsa/pkcs1v22.go:364`, which forces the service indicator false via `src/crypto/internal/fips140/indicator.go:58`.

## Why This Is A Real Bug
The FIPS service indicator is meant to reflect whether the complete cryptographic service used approved parameters. OAEP decryption depends on both the OAEP hash and MGF1 hash. Since the implementation checks only the OAEP hash, it can report an approved operation while using an unchecked and unapproved MGF1 hash.

## Fix Requirement
Call `checkApprovedHash(mgfHash)` in `DecryptOAEP` before any `mgf1XOR` use.

## Patch Rationale
The patch adds approval validation for `mgfHash` alongside the existing validation of the primary OAEP hash. This preserves existing decryption behavior while ensuring the FIPS approval indicator is downgraded when MGF1 uses a non-approved hash.

## Residual Risk
None

## Patch
`065-unchecked-oaep-mgf-hash-approval.patch`