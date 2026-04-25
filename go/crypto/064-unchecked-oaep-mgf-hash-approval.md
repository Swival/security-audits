# Unchecked OAEP MGF Hash Approval

## Classification

Validation gap; severity medium; confidence certain.

## Affected Locations

`src/crypto/internal/fips140/rsa/pkcs1v22.go:397`

## Summary

RSA-OAEP encryption records the operation as FIPS-approved after validating only the OAEP hash. The caller-controlled MGF1 hash is not checked before use, allowing an unapproved MGF hash to be used while the operation is still accounted as approved.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

FIPS accounting is enabled, and the caller supplies an approved OAEP hash with an unapproved `mgfHash` through the OAEP options path.

## Proof

`EncryptOAEP` accepts caller-controlled `mgfHash`, calls `fips140.RecordApproved()`, and validates only `hash` with `checkApprovedHash(hash)`. The unchecked `mgfHash` then reaches `mgf1XOR(db, mgfHash, seed)` and `mgf1XOR(seed, mgfHash, db)`. This permits OAEP encryption to use a non-approved MGF1 hash without recording the operation as non-approved.

The issue is publicly reachable through `EncryptOAEPWithOptions`, which can supply a separate MGF hash. The simpler `crypto/rsa.EncryptOAEP` path passes the same hash for OAEP and MGF, so it does not expose the separate-hash trigger.

## Why This Is A Real Bug

FIPS service-indicator accounting must reflect all cryptographic primitives used by the operation. OAEP encryption uses both the OAEP hash and the MGF1 hash. Validating only the OAEP hash lets a non-approved MGF1 hash participate in an operation that is recorded as approved.

This also creates inconsistent enforcement: decryption validates both hashes, while encryption fails to reject the non-approved MGF hash in FIPS-only mode.

## Fix Requirement

Call `checkApprovedHash(mgfHash)` before any OAEP `mgf1XOR` use, and before recording or preserving approved service-indicator status for the operation.

## Patch Rationale

The patch adds approval validation for `mgfHash` in the OAEP encryption path so both hashes used by RSA-OAEP are checked consistently. This aligns encryption with decryption behavior and prevents false approved accounting when MGF1 uses a non-approved hash.

## Residual Risk

None

## Patch

`064-unchecked-oaep-mgf-hash-approval.patch`