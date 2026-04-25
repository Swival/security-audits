# Unknown Public Curve Panics

## Classification

Error-handling bug. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/boring/ecdh.go:38`

## Summary

`NewPublicKeyECDH` panics when given an unsupported curve string because it calls `curveSize(curve)` before validating the curve with `curveNID(curve)`. The existing error path for unknown curves is therefore unreachable in this path.

## Provenance

Verified from the provided finding and reproducer. Scanner provenance: https://swival.dev

## Preconditions

Caller passes an unsupported curve string to `NewPublicKeyECDH`.

## Proof

`NewPublicKeyECDH` evaluates:

```go
len(bytes) != 1+2*curveSize(curve)
```

before calling:

```go
curveNID(curve)
```

For unsupported strings, `curveSize` reaches its default case and panics:

```go
panic("crypto/internal/boring: unknown curve " + curve)
```

Therefore this call panics instead of returning the existing unknown-curve error:

```go
boring.NewPublicKeyECDH("not-a-curve", nil)
```

Reachability is limited to boringcrypto builds. Current public `crypto/ecdh` callers use fixed supported NIST curve names, but an in-tree/internal caller can still trigger the panic directly.

## Why This Is A Real Bug

`curveNID` already defines an error-return path for unsupported curves, but `NewPublicKeyECDH` performs a size check first through `curveSize`, whose unknown-curve behavior is panic. This creates inconsistent error handling and allows malformed internal input to terminate the process.

## Fix Requirement

Validate the curve with `curveNID(curve)` before any call to `curveSize(curve)`, and return the unknown-curve error when validation fails.

## Patch Rationale

The patch reorders validation so unsupported curve strings are rejected through the existing error path before size-dependent logic runs. Supported curves keep the same behavior because `curveNID` succeeds and the existing length validation still executes afterward.

## Residual Risk

None

## Patch

`068-unknown-public-curve-panics.patch`