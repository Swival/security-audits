# P-521 accepts overlong signature scalars

## Classification

Validation gap. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/ecdsa/ecdsa_s390x.go:172`

## Summary

On s390x with KDSA enabled, P-521 ECDSA verification accepted raw signature scalars longer than the curve-order width. P-521 scalars should be 66 bytes, but the KDSA path only rejected values longer than the 80-byte KDSA block size. Overlong zero-prefixed `R` or `S` values of 67-80 bytes were left-padded into the same KDSA parameter block as their canonical 66-byte encoding.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- s390x KDSA support is enabled.
- P-521 signature verification uses `src/crypto/internal/fips140/ecdsa/ecdsa_s390x.go`.
- Caller supplies raw `fips140/ecdsa.Signature` inputs rather than normal DER through `crypto/ecdsa.VerifyASN1`.

## Proof

`appendBlock` in `src/crypto/internal/fips140/ecdsa/ecdsa_s390x.go` left-pads scalar inputs to the KDSA block size. For P-521, `canUseKDSA` selected an 80-byte block size, while the actual scalar width from `(c.N.BitLen()+7)/8` is 66 bytes.

Therefore, for any valid 66-byte scalar `r`, overlong encodings such as `0x00 || r` up to fourteen leading zero bytes produced the same 80-byte KDSA parameter block as the canonical scalar. That block was then passed to `kdsa`, so if the canonical signature verified, the overlong zero-prefixed variant could verify too.

This violates the package invariant in `src/crypto/internal/fips140/ecdsa/ecdsa.go:271`, which states that `R` and `S` are byte slices of the same length as the curve order.

## Why This Is A Real Bug

The verifier accepted non-canonical raw signature scalars for P-521 on the s390x KDSA path. The local validation checked the KDSA block size instead of the curve-order scalar width, allowing multiple byte encodings of the same scalar to reach the cryptographic backend.

The normal public ASN.1 path is less exposed because DER integer parsing enforces minimal encoding and strips required positive sign padding. However, the raw `fips140/ecdsa.Signature` verifier still had an invalid acceptance condition.

## Fix Requirement

Reject `sig.R` or `sig.S` when either length exceeds `(c.N.BitLen()+7)/8` before constructing KDSA parameter blocks.

## Patch Rationale

The patch adds scalar-width validation before the KDSA block padding step. This preserves KDSA’s fixed-size block formatting while ensuring caller-controlled raw scalars cannot exceed the canonical curve-order byte length.

For P-521, the maximum accepted scalar length is now 66 bytes, not the 80-byte KDSA block size.

## Residual Risk

None

## Patch

`056-p-521-accepts-overlong-signature-scalars.patch`