# Public Key Exposed Mutably

## Classification
Medium vulnerability. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140/ecdsa/ecdsa.go:41`

## Summary
`PublicKey` stores and returns its encoded public point slice without defensive copying. Callers can mutate either the original `Q` slice passed to `NewPublicKey` or the slice returned by `PublicKey.Bytes()`, changing later verification behavior for the same `*PublicKey`.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
Caller obtains a `PublicKey.Bytes()` result before verification, or retains the original `Q` slice passed to `NewPublicKey`.

## Proof
`NewPublicKey` validated the caller-provided encoded point but stored that same slice directly in `PublicKey.q`.

`PublicKey.Bytes()` returned `pub.q` directly.

`verifyGeneric` reparsed `pub.q` during verification using `SetBytes(pub.q)`. Therefore, mutating the returned slice or original input slice after validation changed what key material `Verify` used.

A practical trigger is:
1. Construct a valid `*PublicKey`.
2. Call `pub.Bytes()`.
3. Mutate the returned slice, for example by changing the first byte to an invalid point encoding.
4. Call `Verify`.

The later verification fails during public key parsing, despite the key having been valid when constructed. If mutated to another valid encoded point, verification instead runs against a different public key.

## Why This Is A Real Bug
The type validates public key bytes at construction time but does not preserve the validated value immutably. This violates caller expectations for a key object and allows external mutation to affect future cryptographic verification.

The bug is source-grounded in the internal FIPS ECDSA API: `PublicKey.q` aliases caller-controlled or returned memory, and verification consumes that mutable backing storage later.

## Fix Requirement
Clone `Q` during construction and return a clone from `PublicKey.Bytes()`.

## Patch Rationale
The patch makes `PublicKey` own an immutable copy of the validated public point encoding and prevents callers from acquiring a mutable alias to internal key storage. This preserves existing serialized key behavior while removing post-validation mutation paths.

## Residual Risk
None

## Patch
`025-public-key-exposed-mutably.patch`