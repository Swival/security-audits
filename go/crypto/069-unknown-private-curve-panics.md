# Unknown private curve panics

## Classification

Error-handling bug. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/boring/ecdh.go:65`

## Summary

Unsupported ECDH curve names can panic in BoringCrypto ECDH key parsing/serialization instead of returning an error. `NewPrivateKeyECDH` and `NewPublicKeyECDH` call `curveSize(curve)` before validating that the curve is supported for ECDH.

## Provenance

Verified from the supplied finding and local reproducer evidence. Source: Swival Security Scanner, https://swival.dev

## Preconditions

Caller supplies an unsupported curve string to ECDH key parsing or serialization in `crypto/internal/boring` under the `boringcrypto` build.

## Proof

`curve` enters exported constructors such as:

```go
boring.NewPrivateKeyECDH("bogus", nil)
boring.NewPublicKeyECDH("bogus", nil)
```

Both paths call `curveSize(curve)` before reaching a validating error path. `curveSize` only accepts `P-256`, `P-384`, and `P-521`; any other value hits the default case and panics.

For `"bogus"`, the intended `curveNID` error path is bypassed. For `"P-224"`, `curveNID` may accept the curve name, but ECDH still does not support it, so ECDH-specific validation is required.

## Why This Is A Real Bug

The constructors expose an error-returning API, but invalid caller-controlled curve input can crash the caller process. This violates the documented error-handling contract and creates a reachable denial-of-service condition for direct users of the internal BoringCrypto package.

## Fix Requirement

Validate that the curve is supported for ECDH before calling `curveSize`, or change `curveSize` to return `(int, error)` and propagate that error. The validation must reject unsupported ECDH curves, including names that may be known elsewhere such as `P-224`.

## Patch Rationale

The patch adds ECDH-specific curve validation before size-dependent logic runs. This preserves existing behavior for `P-256`, `P-384`, and `P-521`, while converting unsupported curve names from panics into ordinary returned errors.

## Residual Risk

None

## Patch

`069-unknown-private-curve-panics.patch`