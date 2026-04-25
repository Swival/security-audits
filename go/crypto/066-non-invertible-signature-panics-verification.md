# Non-invertible signature panics verification

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/ecdsa/ecdsa_legacy.go:184`

## Summary

`verifyLegacy` accepts attacker-controlled ASN.1 ECDSA signatures for deprecated custom curves. For custom curves with composite order `N`, a valid-range `s` value may be non-invertible modulo `N`. `ModInverse(s, N)` then returns `nil`, and the verifier passes that nil value into `big.Int.Mul`, causing a panic.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Application verifies ASN.1 ECDSA signatures using deprecated custom curves.
- The custom curve has composite order `N`.
- Attacker can supply a signature with `0 < s < N` and `gcd(s, N) != 1`.

## Proof

`verifyLegacy` parses attacker-controlled `sig` into `r` and `s`, then checks only `0 < r,s < N`.

It calls:

`new(big.Int).ModInverse(s, N)`

For composite `N`, this returns `nil` when `s` has no modular inverse. The returned nil value is then used as the multiplier operand in:

`e.Mul(e, w)`

A reproducer using a minimal custom `elliptic.Curve` with `N = 4` and DER signature `(r=1, s=2)` triggers:

`runtime error: invalid memory address or nil pointer dereference`

The stack reaches `math/big.(*Int).Mul` through `crypto/ecdsa.verifyLegacy`.

## Why This Is A Real Bug

The panic is reachable from attacker-controlled signature input before curve arithmetic is required. The existing bounds check does not guarantee invertibility when `N` is composite. This creates a denial-of-service condition for applications verifying signatures on affected deprecated custom curves.

Standard NIST curves are not affected because their prime orders make every accepted `s` invertible.

## Fix Requirement

Reject signatures when `ModInverse(s, N)` returns `nil` before using the result.

## Patch Rationale

The patch adds an explicit nil check after computing the modular inverse. If no inverse exists, verification returns false instead of panicking. This preserves expected verification semantics: malformed or invalid signatures fail verification.

## Residual Risk

None

## Patch

`066-non-invertible-signature-panics-verification.patch`