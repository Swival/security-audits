# Invalid PKCS#1 Version Accepted

## Classification

Validation gap. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/x509/pkcs1.go:56`

## Summary

`ParsePKCS1PrivateKey` accepts PKCS#1 RSA private keys whose ASN.1 `version` field is negative. The parser only rejects versions greater than `1`, so `-1` bypasses validation, is discarded, and the remaining RSA key fields are returned if mathematically valid.

## Provenance

Verified from supplied finding and runtime reproduction. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller supplies DER for a PKCS#1 RSA private key where:

- The `version` INTEGER is encoded as a negative value, such as `-1`.
- All remaining RSA private key fields are valid.
- `rsa.PrivateKey.Validate()` succeeds.

## Proof

A valid PKCS#1 RSA private key DER can be mutated by changing the leading version INTEGER from `02 01 00` to `02 01 ff`.

`encoding/asn1` accepts `02 01 ff` as the minimal DER encoding of INTEGER `-1` and unmarshals it into `pkcs1PrivateKey.Version`.

The parser then checks only:

```go
if priv.Version > 1 {
```

Because `-1 > 1` is false, the invalid version is accepted. The version is not used afterward. The RSA fields populate `rsa.PrivateKey`, validation succeeds, and `ParsePKCS1PrivateKey` returns the key with `err == nil`.

## Why This Is A Real Bug

PKCS#1 RSA private key versions are constrained to supported non-negative values, currently `0` or `1`. A negative ASN.1 INTEGER is outside the valid domain. Accepting it violates the parser’s format validation contract and permits malformed PKCS#1 input to be treated as valid.

## Fix Requirement

Reject all unsupported versions, including negative values:

```go
priv.Version < 0 || priv.Version > 1
```

## Patch Rationale

The patch tightens the existing version guard from an upper-bound-only check to a closed range check. This preserves acceptance of supported PKCS#1 versions `0` and `1`, while rejecting negative values before the parsed fields are converted into `rsa.PrivateKey`.

## Residual Risk

None

## Patch

`062-invalid-pkcs-1-version-accepted.patch`