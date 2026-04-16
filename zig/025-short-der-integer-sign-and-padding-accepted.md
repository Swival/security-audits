# Short DER Integer Sign and Padding Accepted

## Classification

- Type: `security_control_failure`
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/ecdsa.zig:169`
- Function: `Signature.fromDer`
- Helper: `readDerInt`

## Summary

`Signature.fromDer` accepted non-canonical DER ECDSA signatures when an ASN.1 INTEGER was shorter than the scalar length and its first encoded byte had the high bit set.

The parser zero-initialized the signature, copied short INTEGER values into the tail of the output buffer, then checked the sign bit using `out[0]`. For short values, `out[0]` remained zero padding, so negative/non-DER encodings such as `02 01 80` were accepted instead of rejected.

## Provenance

- Verified by Swival security analysis.
- Scanner: [https://swival.dev](https://swival.dev)

## Preconditions

- A caller parses attacker-supplied DER ECDSA signatures with `Signature.fromDer`.

## Proof

A short DER INTEGER with high-bit first value byte is accepted:

```zig
const der = [_]u8{
    0x30, 0x06,
    0x02, 0x01, 0x80,
    0x02, 0x01, 0x01,
};
const sig = try Scheme.Signature.fromDer(&der);
```

`02 01 80` encodes an INTEGER whose first content byte has the sign bit set. DER requires positive integer 128 to be encoded as:

```text
02 02 00 80
```

Before the patch:

1. `fromDer` zero-initialized `sig`.
2. `readDerInt` copied the one-byte INTEGER into the tail of `out`.
3. `out[0]` remained zero.
4. The sign/padding check used `out[0] >> 7`.
5. The parser observed no sign bit and returned success.

## Why This Is A Real Bug

`Signature.fromDer` is documented to return `InvalidEncoding` for invalid DER encodings. DER INTEGERs used for ECDSA signatures must be non-negative and minimally encoded.

The vulnerable implementation checked sign and padding after zero-padding into the scalar-sized output buffer, using the padded buffer head instead of the first encoded INTEGER byte. This deterministically allowed attacker-controlled non-DER signatures to pass the canonical encoding validator.

## Fix Requirement

Validate DER INTEGER sign and minimal padding against the first encoded content byte before zero-padding can obscure it, or equivalently against the slice containing the encoded bytes after it is read.

Reject:

- Short INTEGERs whose first encoded byte has the high bit set and no DER sign-padding byte was present.
- Non-minimal leading zero padding where the next byte does not require sign protection.

## Patch Rationale

The patch changes the sign-bit comparison from `out[0]` to `out_slice[0]`, which is the first encoded INTEGER byte actually read from DER.

It also adds an explicit minimal-padding check for unnecessary leading zero bytes in the no-sign-padding case.

This preserves valid DER encodings while rejecting the reproduced malformed short negative INTEGER case.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/ecdsa.zig b/lib/std/crypto/ecdsa.zig
index b111b8e52a..709f97a04a 100644
--- a/lib/std/crypto/ecdsa.zig
+++ b/lib/std/crypto/ecdsa.zig
@@ -168,7 +168,8 @@ pub fn Ecdsa(comptime Curve: type, comptime Hash: type) type {
                 }
                 const out_slice = out[out.len - expected_len ..];
                 reader.readSliceAll(out_slice) catch return error.InvalidEncoding;
-                if (@intFromBool(has_top_bit) != out[0] >> 7) return error.InvalidEncoding;
+                if (@intFromBool(has_top_bit) != out_slice[0] >> 7) return error.InvalidEncoding;
+                if (!has_top_bit and out_slice[0] == 0 and expected_len > 1 and out_slice[1] >> 7 == 0) return error.InvalidEncoding;
             }
 
             /// Create a signature from a DER representation.
```