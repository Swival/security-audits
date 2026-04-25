# Multi-Prime Version Mismatch Accepted

## Classification

Validation gap. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/x509/pkcs1.go:56`

## Summary

`ParsePKCS1PrivateKey` accepted PKCS#1 RSA private key DER where `version == 0` but `otherPrimeInfos` was present. This violates PKCS#1’s version invariant: multi-prime RSA private keys must use version `1`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller parses attacker-supplied PKCS#1 RSA private key DER.

## Proof

A valid 3-prime RSA private key was generated and marshaled with `x509.MarshalPKCS1PrivateKey`. The DER version INTEGER was then changed from `1` to `0` without altering the key material.

`x509.ParsePKCS1PrivateKey` accepted the modified DER and returned a valid 3-prime key:

```text
accepted: primes=3 validate=<nil>
```

The parser rejected only `priv.Version > 1`, then appended `priv.AdditionalPrimes` to `key.Primes` regardless of whether `priv.Version` was `0` or `1`. `key.Precompute()` and `key.Validate()` validated RSA mathematical consistency, not the ASN.1 PKCS#1 version invariant.

## Why This Is A Real Bug

The package’s own encoder enforces the inverse invariant: `MarshalPKCS1PrivateKey` emits `version = 1` whenever `len(key.Primes) > 2`.

Accepting `version == 0` with additional primes therefore permits a non-canonical, spec-invalid PKCS#1 structure that the same package would not produce. This is a validation bypass for attacker-controlled private key DER.

## Fix Requirement

Reject PKCS#1 private keys with `len(priv.AdditionalPrimes) > 0` unless `priv.Version == 1`.

## Patch Rationale

The patch adds an explicit parser-side invariant check before constructing or returning the RSA private key. This aligns `ParsePKCS1PrivateKey` with `MarshalPKCS1PrivateKey` and PKCS#1 semantics: two-prime keys use version `0`; multi-prime keys use version `1`.

## Residual Risk

None

## Patch

`063-multi-prime-version-mismatch-accepted.patch`