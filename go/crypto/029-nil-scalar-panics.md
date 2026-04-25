# Nil Scalar Panics

## Classification

Error-handling bug, low severity. Confidence: certain.

## Affected Locations

`src/crypto/ecdsa/ecdsa.go:573`

## Summary

Caller-supplied ECDSA private keys with a supported curve, valid affine public point, and nil `D` scalar can panic in public APIs instead of returning an invalid-key error.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `PrivateKey.Curve` is supported.
- `PrivateKey.X` and `PrivateKey.Y` form a valid affine point for the curve.
- `PrivateKey.D == nil`.
- The malformed key reaches `PrivateKey.Bytes`, `SignASN1`, or deterministic signing.

## Proof

`PrivateKey.Bytes`, `SignASN1`, and deterministic signing dispatch supported curves to `privateKeyToFIPS`.

`privateKeyToFIPS` first calls `pointFromAffine(priv.Curve, priv.X, priv.Y)`. With valid `X` and `Y`, this succeeds.

After that, `privateKeyToFIPS` dereferences `priv.D` without checking for nil:

- `priv.D.BitLen()` at `src/crypto/ecdsa/ecdsa.go:581`
- `priv.D.Sign()` at `src/crypto/ecdsa/ecdsa.go:584`

`math/big.(*Int).BitLen` and `math/big.(*Int).Sign` read receiver internals, so a nil receiver panics.

## Why This Is A Real Bug

The malformed key is reachable through public API inputs because `PrivateKey.D`, `PublicKey.X`, and `PublicKey.Y` are exported fields.

`PrivateKey.Bytes` documents that invalid private keys return an error. A nil `D` scalar is an invalid private key, but the current code panics before returning the documented invalid-key error.

## Fix Requirement

Check `priv.D == nil` before any dereference of `priv.D` in `privateKeyToFIPS`, and return the existing invalid private key error path.

## Patch Rationale

The patch adds an explicit nil-scalar validation before `priv.D.BitLen()` and `priv.D.Sign()`.

This preserves existing behavior for valid keys and non-nil invalid scalars while converting the nil-scalar crash into the documented invalid-key error.

## Residual Risk

None

## Patch

`029-nil-scalar-panics.patch`