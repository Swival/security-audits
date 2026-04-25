# Oversized RSA Exponent Panics

## Classification
Medium severity vulnerability. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140test/acvp_test.go:2082`

## Summary
The ACVP RSA signature verification handler can panic when it receives an RSA public exponent argument longer than four bytes. The panic terminates the wrapper process instead of returning a normal error or invalid verification result.

## Provenance
Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions
ACVP wrapper receives an RSA signature verification request whose exponent argument is longer than four bytes.

## Proof
Request bytes from stdin are parsed into command arguments through `readRequest` and `readArgs`. Registered RSA verification commands, including `RSA/sigVer/SHA2-256/pkcs1v1.5`, are reachable through `processingLoop`.

In `cmdRsaSigVerAft`, the exponent is read from `args[1]` as `eBytes`. The code allocates `paddedE` with length 4, then slices it using:

```go
copy(paddedE[4-len(eBytes):], eBytes)
```

For `len(eBytes) == 5`, the lower slice bound is `-1`, which causes:

```text
runtime error: slice bounds out of range [-1:]
```

A minimal equivalent Go snippet using a five-byte exponent reproduces the panic.

## Why This Is A Real Bug
The handler accepts externally supplied ACVP request data and performs unchecked slicing based on the exponent length. A malformed request can terminate the ACVP wrapper process, creating a denial-of-service condition for that invocation. The expected behavior is to reject malformed input or return an invalid verification result without panicking.

## Fix Requirement
Reject exponent byte strings longer than four bytes before calculating `4-len(eBytes)` or slicing `paddedE`.

## Patch Rationale
The patch adds an explicit length guard before padding the exponent. This preserves the existing four-byte exponent decoding behavior while ensuring oversized inputs follow the normal failure path instead of triggering a runtime panic.

## Residual Risk
None

## Patch
`004-oversized-rsa-exponent-panics.patch`