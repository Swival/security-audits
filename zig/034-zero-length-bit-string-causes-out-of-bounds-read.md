# Zero-Length BIT STRING Causes Out-of-Bounds Read

## Classification

- Type: Out-of-bounds read
- Severity: Medium
- Confidence: Certain
- Impact: Attacker-triggered denial of service via safe-mode bounds-check trap during certificate parsing

## Affected Locations

- `lib/std/crypto/Certificate.zig:570`
- Function: `parseBitString`

## Summary

`Certificate.parse()` parses X.509 BIT STRING fields and delegates validation to `parseBitString`. `parseBitString` validates only the DER tag before reading `cert.buffer[elem.slice.start]` to inspect the unused-bits byte.

A DER BIT STRING with length `0` has `elem.slice.start == elem.slice.end`. If that zero-length BIT STRING is the final certificate signature field and is placed at the end of the certificate, `elem.slice.start == cert.buffer.len`. The indexed read is therefore out of bounds and traps in Zig safe modes.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Finding reproduced: Yes
- Patch supplied: Yes

## Preconditions

- A client parses an attacker-provided certificate.
- Zig safe bounds checks are enabled.
- The attacker can supply a DER certificate containing a zero-length BIT STRING, e.g. a final signature field encoded as `03 00`.

## Proof

`parseBitString` originally contained:

```zig
pub fn parseBitString(cert: Certificate, elem: der.Element) !der.Element.Slice {
    if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
    if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
    return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
}
```

`der.Element.parse` accepts short-form length `0` and returns an empty content slice:

```zig
.slice = .{
    .start = i,
    .end = i + size_byte,
}
```

For `size_byte == 0`, `start == end`.

A minimal DER certificate with a final signature BIT STRING ending in `03 00` reproduced the issue. Calling `Certificate.parse()` in Debug mode produced:

```text
panic: index out of bounds: index 103, len 103
.../lib/std/crypto/Certificate.zig:565:20: in parseBitString
    if (cert.buffer[elem.slice.start] != 0) ...
```

Attack path:

1. A malicious TLS server sends a crafted certificate.
2. The Zig TLS client parses the peer certificate.
3. The final signature BIT STRING has zero length.
4. `parseBitString` reads `cert.buffer[elem.slice.start]`.
5. `elem.slice.start == cert.buffer.len`.
6. Zig traps on the out-of-bounds indexed read.

## Why This Is A Real Bug

A DER BIT STRING content value must contain at least one byte: the initial unused-bits count. A zero-length BIT STRING is invalid and should be rejected before reading its first content byte.

The vulnerable code assumes this byte exists. Since certificate bytes are attacker-controlled in a TLS handshake and parsing occurs before certificate trust validation, a malicious peer can trigger a client process panic. This is a remotely reachable denial-of-service condition.

## Fix Requirement

Reject BIT STRING elements with an empty content slice before reading the unused-bits byte.

Required condition:

```zig
if (elem.slice.start >= elem.slice.end) return error.CertificateHasInvalidBitString;
```

This must occur after confirming the tag is `.bitstring` and before indexing `cert.buffer[elem.slice.start]`.

## Patch Rationale

The patch adds an explicit non-empty-content check to `parseBitString`.

For valid DER BIT STRINGs, `elem.slice.start < elem.slice.end`, so behavior is unchanged.

For malformed zero-length BIT STRINGs, `parseBitString` now returns `error.CertificateHasInvalidBitString` instead of performing an out-of-bounds read. This converts attacker-controlled malformed input into a normal parse failure.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/Certificate.zig b/lib/std/crypto/Certificate.zig
index 4defc2a408..07519ef60b 100644
--- a/lib/std/crypto/Certificate.zig
+++ b/lib/std/crypto/Certificate.zig
@@ -562,6 +562,7 @@ pub const ParseBitStringError = error{ CertificateFieldHasWrongDataType, Certifi
 
 pub fn parseBitString(cert: Certificate, elem: der.Element) !der.Element.Slice {
     if (elem.identifier.tag != .bitstring) return error.CertificateFieldHasWrongDataType;
+    if (elem.slice.start >= elem.slice.end) return error.CertificateHasInvalidBitString;
     if (cert.buffer[elem.slice.start] != 0) return error.CertificateHasInvalidBitString;
     return .{ .start = elem.slice.start + 1, .end = elem.slice.end };
 }
```