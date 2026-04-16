# Uncompressed SEC1 Identity Is Accepted

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/std/crypto/pcurves/secp256k1.zig:152`
- `Secp256k1.fromSec1`, uncompressed SEC1 tag `0x04` branch
- `Secp256k1.fromAffineCoordinates`

## Summary

`Secp256k1.fromSec1()` accepted an invalid uncompressed SEC1 encoding of the point at infinity:

```text
04 || 0000000000000000000000000000000000000000000000000000000000000000
   || 0000000000000000000000000000000000000000000000000000000000000001
```

SEC1 permits the point at infinity only as the single byte `0x00`. It must not be accepted as an uncompressed affine point. The parser decoded the `x=0, y=1` coordinates and delegated to `fromAffineCoordinates()`, which treats those coordinates as the internal identity representation and returns success.

## Provenance

Reproduced and patched from a verified Swival security finding.

Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)

Confidence: certain.

## Preconditions

- Caller uses `Secp256k1.fromSec1()` to enforce SEC1 point encoding validity.
- Attacker can supply a SEC1-encoded secp256k1 point.

## Proof

The affected uncompressed SEC1 input is 65 bytes:

```text
04
0000000000000000000000000000000000000000000000000000000000000000
0000000000000000000000000000000000000000000000000000000000000001
```

Execution path:

1. `fromSec1()` reads tag `0x04`.
2. The `0x04` branch requires `encoded.len == 64`, which the input satisfies.
3. It parses:
   - `x = 0`
   - `y = 1`
4. It calls:

   ```zig
   return Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y });
   ```

5. `fromAffineCoordinates()` computes:

   ```zig
   const is_identity =
       @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) &
       @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
   ```

6. Since `AffineCoordinates.identityElement` is `(0, 1)`, `is_identity` is true.
7. The function rejects only when neither `on_curve` nor `is_identity` is true:

   ```zig
   if ((on_curve | is_identity) == 0) {
       return error.InvalidEncoding;
   }
   ```

8. It then conditionally moves `z` to zero:

   ```zig
   ret.z.cMov(Secp256k1.identityElement.z, is_identity);
   ```

9. The result is a successful return of the internal identity element.

Runtime reproduction confirmed that `Secp256k1.fromSec1()` returns success for this input and that the resulting point is rejected by `rejectIdentity()` as `IdentityElement`.

## Why This Is A Real Bug

SEC1 has a distinct encoding for the point at infinity: a single byte `0x00`.

An uncompressed SEC1 point with tag `0x04` represents affine coordinates and must contain a valid affine curve point. The coordinate pair `(0, 1)` is not a valid secp256k1 affine point, because for secp256k1:

```text
y² = x³ + 7
```

For `(x=0, y=1)`:

```text
1² != 0³ + 7
1 != 7
```

The parser therefore accepts an encoding it is required to reject. This breaks callers that rely on `fromSec1()` as a SEC1 validity gate.

## Fix Requirement

Reject the internal identity affine sentinel `(x=0, y=1)` in the uncompressed SEC1 `0x04` branch.

Only tag `0x00` may encode the point at infinity.

## Patch Rationale

The patch adds an explicit identity-coordinate rejection after parsing uncompressed coordinates and before delegating to `fromAffineCoordinates()`:

```zig
if (x.equivalent(AffineCoordinates.identityElement.x) and y.equivalent(AffineCoordinates.identityElement.y)) return error.InvalidEncoding;
```

This preserves existing behavior for the valid SEC1 infinity encoding `0x00`, while preventing the invalid uncompressed identity representation from being accepted.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/pcurves/secp256k1.zig b/lib/std/crypto/pcurves/secp256k1.zig
index 1c1caae19a..1b36344598 100644
--- a/lib/std/crypto/pcurves/secp256k1.zig
+++ b/lib/std/crypto/pcurves/secp256k1.zig
@@ -149,6 +149,7 @@ pub const Secp256k1 = struct {
                 if (encoded.len != 64) return error.InvalidEncoding;
                 const x = try Fe.fromBytes(encoded[0..32].*, .big);
                 const y = try Fe.fromBytes(encoded[32..64].*, .big);
+                if (x.equivalent(AffineCoordinates.identityElement.x) and y.equivalent(AffineCoordinates.identityElement.y)) return error.InvalidEncoding;
                 return Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y });
             },
             else => return error.InvalidEncoding,
```