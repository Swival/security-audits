# Zero Certificate Serial Accepted

## Classification

Validation gap, low severity, confidence: certain.

## Affected Locations

`src/crypto/x509/x509.go:1688`

## Summary

`CreateCertificate` accepted `template.SerialNumber == big.NewInt(0)` because it rejected only negative serial numbers. This allowed the public certificate creation API to emit an RFC 5280-invalid certificate with a non-positive serial number.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller supplies `template.SerialNumber` equal to zero.

## Proof

`CreateCertificate` uses `template.SerialNumber` unless it is `nil`, then validates it with a negative-only check:

```go
if serialNumber.Sign() == -1
```

For `big.NewInt(0)`, `Sign()` returns `0`, so validation succeeds. The accepted zero value is assigned into `tbsCertificate.SerialNumber` and marshaled into the signed certificate. ASN.1 integer marshaling supports zero, so encoding succeeds rather than rejecting the value.

A related edge case also exists when `template.SerialNumber == nil`: if the caller-controlled `rand io.Reader` returns all zero bytes, generated serial generation can produce zero and pass the same incomplete check.

## Why This Is A Real Bug

RFC 5280 requires certificate serial numbers to be positive. A zero serial number is non-positive and invalid. The affected public API can create such a certificate, and the local parser rejects only negative serials, making the invalid output locally parseable.

## Fix Requirement

Reject all non-positive serial numbers before marshaling:

```go
serialNumber.Sign() <= 0
```

The same validation must apply to caller-provided and generated serial numbers.

## Patch Rationale

The patch changes serial-number validation from negative-only rejection to non-positive rejection. This closes the direct `template.SerialNumber == 0` path and prevents all-zero generated serials from being emitted.

## Residual Risk

None

## Patch

`006-zero-certificate-serial-accepted.patch`