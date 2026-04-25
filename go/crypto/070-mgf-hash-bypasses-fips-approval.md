# MGF hash bypasses FIPS approval

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/rsa/fips.go:229`

## Summary

OAEP encryption validates the primary OAEP hash in FIPS 140-only mode but does not validate the caller-controlled MGF hash. As a result, encryption can proceed with an unapproved `MGFHash` while the operation remains reachable as FIPS-approved.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

FIPS 140-only mode is enabled.

OAEP options specify an approved `Hash` and an unapproved `MGFHash`.

## Proof

`EncryptOAEPWithOptions` accepts caller-controlled `opts.MGFHash` and passes `opts.MGFHash.New()` into `encryptOAEP`.

`encryptOAEP` unwraps and validates only `hash` with `ApprovedHash(hash)`, then passes both `hash` and unchecked `mgfHash` to `rsa.EncryptOAEP`.

The internal OAEP implementation checks the approved status of `hash`, but uses `mgfHash` for MGF1 without a corresponding approval check.

This permits FIPS-only OAEP encryption to complete with an unapproved MGF hash.

## Why This Is A Real Bug

FIPS 140-only mode requires non-approved cryptographic algorithms to be rejected or fail before use.

The MGF hash is cryptographically material to OAEP encoding. Allowing an unapproved MGF hash while treating the RSA-OAEP operation as approved violates the FIPS enforcement boundary.

The SHA-1 nuance does not invalidate the issue: SHA-1 may fail through its own implementation in FIPS-only mode, but `crypto.Hash.New` is registry-based and can supply other non-approved hash implementations. The RSA OAEP path itself does not reject them.

## Fix Requirement

Unwrap `mgfHash` and require `ApprovedHash(mgfHash)` before calling `rsa.EncryptOAEP`.

## Patch Rationale

The patch adds the missing approval validation for the OAEP MGF hash on the encryption path, matching the security requirement already applied to the primary OAEP hash and preventing unchecked use of caller-controlled MGF algorithms in FIPS-only mode.

## Residual Risk

None

## Patch

`070-mgf-hash-bypasses-fips-approval.patch`