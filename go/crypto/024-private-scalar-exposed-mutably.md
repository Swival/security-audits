# Private Scalar Exposed Mutably

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/ecdsa/ecdsa.go:28`

## Summary

`PrivateKey.Bytes()` returns `priv.d` directly, exposing the internal private scalar slice by mutable alias. A caller can modify the returned slice and thereby mutate the signing scalar after key construction, while the stored public key remains unchanged.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

Caller can access a `*PrivateKey` and invoke `Bytes()` before signing.

## Proof

`PrivateKey.Bytes()` returns the internal `priv.d` slice directly.

A caller can:

1. Obtain a valid `*PrivateKey`.
2. Call `b := priv.Bytes()`.
3. Overwrite `b` with another fixed-length scalar.
4. Call `Sign` or `SignDeterministic`.

Signing later reads `priv.d` for deterministic nonce state and scalar multiplication in `s = k^-1(e + r*d)`. The public key remains the original stored public key. Validation only checks the stored public key curve, not whether `pub.q == [d]G`.

This proves the returned slice aliases secret mutable state and can corrupt or replace the signing scalar after construction.

## Why This Is A Real Bug

The private scalar is security-sensitive internal state. Publicly returning it by mutable alias violates key immutability and allows callers to alter `d` without revalidating the key pair invariant.

Valid scalar mutations make signatures correspond to the mutated scalar rather than the unchanged public key. Invalid scalar mutations corrupt the key and can cause signing failure. Both outcomes are reachable through a public method.

## Fix Requirement

`PrivateKey.Bytes()` must return a copy of the private scalar, not the backing slice.

Required change:

```go
return bytes.Clone(priv.d)
```

## Patch Rationale

Cloning preserves the existing API behavior of returning the private scalar bytes while preventing callers from mutating `priv.d`. This restores encapsulation of the private key and preserves the invariant established during key construction.

## Residual Risk

None

## Patch

Patch file: `024-private-scalar-exposed-mutably.patch`

The patch updates `src/crypto/internal/fips140/ecdsa/ecdsa.go` so `PrivateKey.Bytes()` returns `bytes.Clone(priv.d)` instead of `priv.d`.