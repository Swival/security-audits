# Trailing ECH Extension Bytes Accepted

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/ech.go:550`

## Summary

`parseECHExt` accepts malformed outer ECH extensions that contain valid encoded fields followed by trailing bytes. The parser reads the outer ECH type, KDF, AEAD, config ID, encapsulated key, and payload, then returns success without verifying that the input is exhausted. This allows malformed outer ECH extension data to proceed to HPKE/decode handling instead of being rejected with `errMalformedECHExt`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A server processes a ClientHello containing an outer ECH extension with valid fields followed by extra trailing bytes.

## Proof

The outer ECH parser path reads all expected fields but does not check for remaining bytes after the payload length-prefixed field.

A standalone parser PoC mirroring the committed function used this ECH extension body:

```text
00 0001 0001 07 0003 010203 0003 040506 dead
```

Result:

```text
err=<nil>
trailing bytes ignored=2
```

The parser returned the expected decoded fields while ignoring the final `dead` bytes. The malformed outer ECH extension therefore reaches later HPKE/decode handling instead of failing with `errMalformedECHExt`.

The inner ECH path already rejects trailing data at `src/crypto/tls/ech.go:516`, so the validation gap is specific to the outer ECH parsing path. The same parser is also used for a second ClientHello after HRR at `src/crypto/tls/handshake_server_tls13.go:596`.

## Why This Is A Real Bug

TLS extension parsers must reject malformed encodings with trailing data. Accepting trailing bytes creates inconsistent validation between inner and outer ECH extensions and permits non-canonical malformed outer ECH input to progress beyond parsing. A custom ECH client can compute HPKE AAD over the exact malformed outer ClientHello, so this is not merely an unreachable parser state.

## Fix Requirement

After reading the outer ECH payload, reject the extension unless the parser input is exhausted.

## Patch Rationale

The patch adds an `s.Empty()` check after parsing the outer ECH payload. If any trailing bytes remain, `parseECHExt` returns `errMalformedECHExt`, matching the existing strict behavior in the inner ECH parsing path.

## Residual Risk

None

## Patch

`011-trailing-ech-extension-bytes-accepted.patch`