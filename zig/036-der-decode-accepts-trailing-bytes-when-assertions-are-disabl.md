# DER Decode Accepts Trailing Bytes When Assertions Are Disabled

## Classification

security_control_failure, high severity

## Affected Locations

- `lib/std/crypto/codecs/asn1/der.zig:13`

## Summary

`der.decode` parsed a DER value and enforced full input consumption only with `std.debug.assert(decoder.index == encoded.len)`. In assertion-disabled builds, a valid DER value followed by trailing attacker-controlled bytes was accepted as valid input. DER decoding must reject non-fully-consumed encodings.

## Provenance

Verified by Swival security analysis and reproduction.

- Scanner: https://swival.dev
- Confidence: certain

## Preconditions

- Caller invokes `der.decode` on untrusted data.
- Assertions are disabled, such as in `ReleaseFast` or `ReleaseSmall` builds.

## Proof

The affected implementation initialized a `Decoder` over the full byte slice, parsed one value with `decoder.any(T)`, and then used only a debug assertion to check that the decoder consumed the entire input:

```zig
const res = try decoder.any(T);
std.debug.assert(decoder.index == encoded.len);
return res;
```

For input containing a valid DER integer followed by a trailing byte:

```text
02 01 05 ff
```

the parser consumes the integer `5`, leaving `decoder.index == 3` while `encoded.len == 4`.

Observed behavior from reproduction:

- Debug build on `020105ff`: panics at the full-consumption assertion.
- ReleaseFast build on `020105ff`: successfully decodes integer `5`.
- ReleaseFast build on valid `020105`: also decodes integer `5`.

Thus, in assertion-disabled builds, malformed DER with trailing bytes is accepted equivalently to valid DER.

## Why This Is A Real Bug

DER is a strict encoding format and requires a single, fully consumed encoded value. Accepting trailing data violates DER validation semantics and causes the parser to fail open on non-DER input.

The affected module is under `std.crypto.codecs.asn1`, documents DER as used in PKI, and performs security-relevant decoding. Relying on `std.debug.assert` for input validation is unsafe because assertions are not runtime checks in optimized builds.

## Fix Requirement

Replace the debug-only assertion with a runtime error when parsed input does not consume the entire byte slice.

## Patch Rationale

The patch changes the full-consumption check from a build-mode-dependent assertion to an unconditional runtime validation:

```zig
if (decoder.index != encoded.len) return error.TrailingBytes;
```

This preserves successful decoding for valid DER while rejecting inputs that contain trailing bytes in all build modes.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/codecs/asn1/der.zig b/lib/std/crypto/codecs/asn1/der.zig
index 4395f9f3b6..27dabcd111 100644
--- a/lib/std/crypto/codecs/asn1/der.zig
+++ b/lib/std/crypto/codecs/asn1/der.zig
@@ -11,7 +11,7 @@ pub const Encoder = @import("der/Encoder.zig");
 pub fn decode(comptime T: type, encoded: []const u8) !T {
     var decoder = Decoder{ .bytes = encoded };
     const res = try decoder.any(T);
-    std.debug.assert(decoder.index == encoded.len);
+    if (decoder.index != encoded.len) return error.TrailingData;
     return res;
 }
 
```