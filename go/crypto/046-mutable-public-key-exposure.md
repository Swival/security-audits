# Mutable Public Key Exposure

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/ecdh/ecdh.go:43`

## Summary

`PublicKey.Bytes` exposes the mutable internal `PublicKey.q` backing array. Callers can mutate the returned slice after `NewPublicKey` validation, breaking the invariant that `q` contains the originally accepted valid public-key encoding. Later ECDH operations consume the mutated bytes.

## Provenance

Verified from the supplied finding and reproducer. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller retains or receives the result of `PublicKey.Bytes` and mutates that returned slice.

## Proof

`NewPublicKey` validates the input key and stores `bytes.Clone(key)` in `PublicKey.q`, establishing that `q` is a validated encoded point.

`PublicKey.Bytes` returns `pub.q` directly. Because slices are mutable references to backing arrays, a caller can mutate the returned value:

```go
b := pub.Bytes()
b[0] = 0
```

or replace it with another same-curve encoded point:

```go
copy(b, otherValidPoint)
```

ECDH later calls `SetBytes(peer.q)`, so it consumes the caller-mutated bytes rather than the originally validated key. Reproduction showed two practical outcomes:

- Mutating the bytes to an invalid encoding makes a previously accepted `PublicKey` fail during ECDH.
- Mutating the bytes to another valid same-curve point makes ECDH compute a shared secret for the substituted public key.

Scope note: the public `crypto/ecdh` wrapper returns a copy from its own `PublicKey.Bytes`, so this is not directly exposed through the public `crypto/ecdh` API. The invariant break exists in `crypto/internal/fips140/ecdh`.

## Why This Is A Real Bug

The type validates public-key bytes on construction, but then exposes the validated internal storage for mutation. That invalidates the post-construction integrity guarantee of `PublicKey.q`. ECDH trusts `peer.q` as the accepted public key state, so external mutation can change later cryptographic behavior or cause failure after successful validation.

## Fix Requirement

`PublicKey.Bytes` must return a defensive copy:

```go
return bytes.Clone(pub.q)
```

## Patch Rationale

Returning a clone preserves the existing API behavior while preventing callers from modifying `PublicKey.q`. This aligns `PublicKey.Bytes` with the constructor’s defensive-copy behavior and restores the invariant that accepted public keys remain immutable after validation.

## Residual Risk

None

## Patch

`046-mutable-public-key-exposure.patch`