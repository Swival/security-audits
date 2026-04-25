# HKDF Label Length Truncation

## Classification

Medium severity validation gap. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/tls13/tls13.go:33`

## Summary

`ExpandLabel` accepted lengths outside the TLS 1.3 HKDF label encoding range. It encoded `length` as `uint16(length)` while passing the original integer length to `hkdf.Expand`, allowing values above `65535` to wrap in the label field.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller invokes exported `ExpandLabel` or `Exporter` with `length > 65535`.

## Proof

- `length` reaches `ExpandLabel` directly, including through `Exporter`.
- `ExpandLabel` encodes the HKDF label length with `uint16(length)`.
- For `length == 65536`, the encoded two-byte length becomes `0`.
- The original oversized `length` is still passed to `hkdf.Expand`.
- In the public TLS 1.3 EKM path, committed SHA-256/SHA-384 suites cannot produce that much HKDF output, so `hkdf.Expand` panics with `hkdf: counter overflow` instead of returning an error.
- The broader mismatched-label derivation is possible for internal `ExpandLabel` callers using a custom large-output `hash.Hash`.

## Why This Is A Real Bug

TLS 1.3 HKDF labels encode output length in two bytes. Accepting larger lengths violates the label format and creates inconsistent behavior between the encoded label and requested HKDF output. In the public TLS exporter path, this becomes an unhandled panic reachable through caller-controlled length.

## Fix Requirement

Reject invalid lengths before encoding: `length < 0` or `length > 65535`.

## Patch Rationale

The patch adds explicit bounds validation before `byteorder.BEAppendUint16` is called. This prevents truncation, preserves RFC-compatible HKDF label encoding, and converts the oversized public exporter case from a panic into controlled rejection.

## Residual Risk

None

## Patch

`051-hkdf-label-length-truncation.patch`