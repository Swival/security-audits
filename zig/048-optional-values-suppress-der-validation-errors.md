# Optional DER Values Suppress Validation Errors

## Classification

- Finding type: security control failure
- Severity: high
- Confidence: certain

## Affected Locations

- `lib/std/crypto/codecs/asn1/der/Decoder.zig:77`

## Summary

The DER decoder treats every error while decoding an optional field as absence of that field. This suppresses validation errors for malformed present optional values, allowing non-DER- canonical encodings to be accepted.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Finding reproduced and patched from the verified report.

## Preconditions

- The target schema contains an optional DER field.

## Proof

A schema with an optional boolean accepts a malformed DER boolean:

```zig
const S = struct {
    b: ?bool,
};

const bytes = [_]u8{ 0x30, 0x03, 0x01, 0x01, 0x01 };
// SEQUENCE { BOOLEAN 0x01 }, where 0x01 is not a valid DER BOOLEAN encoding.

const s = try der.decode(S, &bytes);
```

Expected behavior: reject the input with `error.InvalidBool`.

Observed behavior: decoding succeeds and `s.b == null`.

Propagation path:

1. `der.decode(S, bytes)` calls `Decoder.any(S)`.
2. Struct decoding enters the sequence and decodes field `b: ?bool`.
3. Optional decoding calls `self.any(bool)`.
4. Boolean decoding calls `element(boolean)`, which matches the tag and advances `index` past the malformed BOOLEAN.
5. Boolean validation sees byte `0x01` and returns `error.InvalidBool`.
6. Optional decoding catches that error and returns `null`.
7. Struct decoding completes successfully.
8. The top-level `decoder.index == encoded.len` check still passes because the invalid element was already consumed.

The vulnerable code is:

```zig
.optional => |o| return self.any(o.child) catch return null,
```

## Why This Is A Real Bug

DER parsing is intended to enforce canonical DER rules, including rejecting invalid booleans and non-canonical integers. Optional fields may be absent, but a present optional field with invalid encoding must not be treated as absent.

The current implementation catches all child decode errors. This conflates:

- `error.UnexpectedElement`: the optional field is absent.
- Validation errors such as `error.InvalidBool`, `error.NonCanonical`, or `error.LargeValue`: the optional field is present but invalid.

Because `element()` advances the decoder index after matching the tag, malformed present optionals can be consumed and then silently ignored.

## Fix Requirement

Optional decoding must only return `null` when the child field is absent. It must propagate all validation, canonicalization, and decoding errors from a present child value.

Specifically:

- Catch `error.UnexpectedElement` and return `null`.
- Propagate every other error.

## Patch Rationale

The patch preserves optional-field absence handling while preventing malformed present values from failing open.

`error.UnexpectedElement` is the decoder signal that the next element does not match the expected optional child tag. That is the only condition that should map to `null`.

All other errors indicate that parsing reached the child value and failed validation or decoding. Those errors must remain visible to callers.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/codecs/asn1/der/Decoder.zig b/lib/std/crypto/codecs/asn1/der/Decoder.zig
index 25a4139d6e..3eae856e1b 100644
--- a/lib/std/crypto/codecs/asn1/der/Decoder.zig
+++ b/lib/std/crypto/codecs/asn1/der/Decoder.zig
@@ -74,7 +74,10 @@ pub fn any(self: *Decoder, comptime T: type) !T {
             }
             return @enumFromInt(try int(e.tag_type, bytes));
         },
-        .optional => |o| return self.any(o.child) catch return null,
+        .optional => |o| return self.any(o.child) catch |err| switch (err) {
+            error.UnexpectedElement => null,
+            else => return err,
+        },
         else => @compileError("cannot decode type " ++ @typeName(T)),
     }
 }
```