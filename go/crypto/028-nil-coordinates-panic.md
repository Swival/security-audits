# Nil Coordinates Panic

## Classification

Validation gap. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/ecdsa/ecdsa.go:599`

## Summary

Caller-supplied ECDSA public keys with a supported curve but nil `X` or `Y` coordinates can panic during conversion, serialization, ECDH, or verification paths. The code dereferences nil `*big.Int` coordinates instead of returning the documented invalid-key error or verification failure.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller supplies a `crypto/ecdsa.PublicKey` with:

- Supported `Curve`
- Nil `X` or nil `Y`

## Proof

`PublicKey.Bytes`, `ECDH`, `VerifyASN1`, and signing conversion paths can reach `publicKeyToFIPS` or `privateKeyToFIPS`.

`publicKeyToFIPS` passes `pub.X` and `pub.Y` directly to `pointFromAffine`.

`pointFromAffine` then calls `x.Sign()` and `y.Sign()` without checking whether either coordinate is nil. A nil coordinate therefore dereferences a nil `*big.Int` and triggers:

```text
runtime error: invalid memory address or nil pointer dereference
```

Runtime reproduction confirmed:

- `PublicKey.Bytes()` panics with nil `X`
- `PublicKey.Bytes()` panics with nil `Y`
- `VerifyASN1()` panics when given a syntactically valid ASN.1 signature and a public key with nil coordinates

## Why This Is A Real Bug

Malformed caller-supplied public keys should be rejected as invalid. Instead, several reachable public APIs can crash the process by dereferencing nil coordinate fields.

This violates expected error-return behavior for invalid keys and can turn malformed input into a denial-of-service condition in applications that process externally supplied ECDSA public keys.

## Fix Requirement

`pointFromAffine` must reject nil coordinates before calling methods on `x` or `y`.

## Patch Rationale

The patch adds explicit nil checks for `x` and `y` in `pointFromAffine` and returns an invalid-key error before any coordinate method calls occur.

This fixes the root cause at the shared conversion helper, covering all callers that route through affine-to-FIPS conversion.

## Residual Risk

None

## Patch

`028-nil-coordinates-panic.patch`