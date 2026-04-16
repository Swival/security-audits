# Explicit Field Wrapper Length Is Not Enforced

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/std/crypto/codecs/asn1/der/Decoder.zig:34`

## Summary

The DER decoder accepts malformed ASN.1 DER where bytes belonging to later sibling fields are incorrectly placed inside an explicitly tagged field wrapper.

For explicitly tagged struct fields, `Decoder.any` enters the explicit wrapper, decodes only the child value, and then continues decoding subsequent struct fields without verifying that the explicit wrapper was fully consumed. This lets malformed DER pass structural validation.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The target Zig struct has an explicit ASN.1 field.
- That explicit field is followed by at least one additional field.
- An attacker can provide DER input to the decoder.

## Proof

For a struct with an explicitly tagged field `a` followed by sibling field `b`, the following malformed DER is accepted:

```text
30 08          ; SEQUENCE len 8
   A0 06       ; [0] EXPLICIT len 6
      02 01 01 ; INTEGER 1, intended a
      02 01 02 ; INTEGER 2, should be sibling b, but is inside [0]
```

Observed behavior:

```text
der.decode(T, malformed) succeeds
a=1 b=2
```

Execution flow:

1. Outer `SEQUENCE` sets `self.index` to the sequence body.
2. Explicit `[0]` wrapper sets `self.index` to the wrapper body start.
3. Field `a` consumes only the first inner integer.
4. `self.index` remains inside the explicit wrapper.
5. The struct field loop continues.
6. Field `b` is decoded from bytes still inside the explicit wrapper.
7. The decoder returns success for DER that violates the declared structure.

## Why This Is A Real Bug

DER is a strict encoding. An explicitly tagged field is a wrapper whose contents must contain exactly the encoded child value for that field. Bytes for later sibling fields must not be accepted from inside that wrapper.

The vulnerable code records the explicit wrapper element but only resets `self.index` to `seq.slice.start`. It does not require `self.index == seq.slice.end` after decoding the explicit child. Therefore, malformed nesting is accepted as valid input.

This is a deterministic fail-open in structure enforcement.

## Fix Requirement

After decoding an explicitly tagged field’s child value, the decoder must verify that the explicit wrapper has been fully consumed before continuing to subsequent struct fields.

Required check:

```zig
if (self.index != explicit_wrapper_end) return error.UnexpectedElement;
```

## Patch Rationale

The patch records the end offset of an explicit wrapper before decoding its child:

```zig
var explicit_end: ?Index = null;
...
explicit_end = seq.slice.end;
```

After the field value is decoded, it verifies that parsing ended exactly at the wrapper boundary:

```zig
if (explicit_end) |end| {
    if (self.index != end) return error.UnexpectedElement;
}
```

This preserves valid explicit-field decoding while rejecting malformed DER that contains extra bytes or sibling fields inside the explicit wrapper.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/codecs/asn1/der/Decoder.zig b/lib/std/crypto/codecs/asn1/der/Decoder.zig
index 25a4139d6e..b24cc8f7f4 100644
--- a/lib/std/crypto/codecs/asn1/der/Decoder.zig
+++ b/lib/std/crypto/codecs/asn1/der/Decoder.zig
@@ -28,11 +28,13 @@ pub fn any(self: *Decoder, comptime T: type) !T {
             inline for (info.field_names, info.field_types, info.field_attrs) |f_name, f_type, f_attrs| {
                 self.field_tag = FieldTag.fromContainer(T, f_name);
 
+                var explicit_end: ?Index = null;
                 if (self.field_tag) |ft| {
                     if (ft.explicit) {
                         const seq = try self.element(ft.toTag().toExpected());
                         self.index = seq.slice.start;
                         self.field_tag = null;
+                        explicit_end = seq.slice.end;
                     }
                 }
 
@@ -42,6 +44,9 @@ pub fn any(self: *Decoder, comptime T: type) !T {
                     }
                     return err;
                 };
+                if (explicit_end) |end| {
+                    if (self.index != end) return error.UnexpectedElement;
+                }
                 // DER encodes null values by skipping them.
                 if (@typeInfo(f_type) == .optional and @field(res, f_name) == null) {
                     if (f_attrs.defaultValue(f_type)) |d| @field(res, f_name) = d;
```