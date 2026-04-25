# Trailing DER Accepted

## Classification

Validation gap. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/x509/sec1.go:87`

## Summary

`ParseECPrivateKey` accepted non-canonical DER containing a valid SEC 1 EC private key followed by trailing bytes. The parser called `asn1.Unmarshal` but discarded the returned `rest` slice, allowing appended DER objects or arbitrary bytes to be ignored.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller relies on `x509.ParseECPrivateKey` to reject non-canonical DER with trailing data.

## Proof

A valid `EC PRIVATE KEY` DER object followed by extra DER bytes, such as `05 00` (`NULL`), was accepted.

Reachability:

- Public `x509.ParseECPrivateKey` calls `parseECPrivateKey(nil, der)` at `src/crypto/x509/sec1.go:36`.
- `parseECPrivateKey` calls `asn1.Unmarshal(der, &privKey)` at `src/crypto/x509/sec1.go:87`.
- The returned trailing `rest` slice was discarded.
- Parsing then continued through version, curve OID, scalar normalization, and `ecdsa.ParseRawPrivateKey`.
- Runtime PoC confirmed `x509.ParseECPrivateKey` returned `err=<nil>` and produced the same private scalar after appending `05 00`.

## Why This Is A Real Bug

`encoding/asn1.Unmarshal` explicitly returns trailing bytes as `rest`. A parser for a single DER object must reject non-empty `rest` to enforce canonical parsing. Ignoring `rest` allows inputs that contain a valid leading EC private key plus extra trailing data to be accepted as valid.

## Fix Requirement

Capture the `rest` value returned by `asn1.Unmarshal` and reject the input when `len(rest) != 0`.

## Patch Rationale

The patch makes `parseECPrivateKey` enforce single-object DER semantics by checking for trailing data immediately after ASN.1 unmarshalling. This preserves existing validation for valid keys while rejecting inputs that contain appended bytes.

## Residual Risk

None

## Patch

`039-trailing-der-accepted.patch`