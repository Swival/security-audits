# Uncompressed Infinity Bypasses P-384 Point Validation

## Classification

Security control failure, high severity. Confidence: certain.

## Affected Locations

- `lib/std/crypto/pcurves/p384.zig:54`
- Function: `P384.fromAffineCoordinates`
- Caller path: `P384.fromSec1`, uncompressed SEC1 encoding type `0x04`

## Summary

`P384.fromSec1` accepts an invalid uncompressed SEC1 point encoding with affine coordinates `x = 0, y = 1`. These coordinates are not on P-384, but `fromAffineCoordinates` treats them as the affine representation of the identity element and converts the decoded point to `P384.identityElement` instead of returning `error.InvalidEncoding`.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: https://swival.dev

## Preconditions

- A caller relies on `P384.fromSec1` to reject invalid P-384 public keys.
- Attacker can provide a SEC1-encoded P-384 point.
- The provided point uses uncompressed SEC1 encoding: `0x04 || x || y`.

## Proof

In `P384.fromAffineCoordinates`:

```zig
const on_curve = @intFromBool(x3AxB.equivalent(yy));
const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) & @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
if ((on_curve | is_identity) == 0) {
    return error.InvalidEncoding;
}
var ret = P384{ .x = x, .y = y, .z = Fe.one };
ret.z.cMov(P384.identityElement.z, is_identity);
return ret;
```

For the malicious uncompressed SEC1 input:

```text
04 || x=0 || y=1
```

Observed behavior:

- `x = 0` and `y = 1` are canonical field encodings, so `Fe.fromBytes` succeeds.
- The point is not on P-384:
  - at `x = 0`, curve RHS is `B`
  - `y² = 1`
  - P-384 constant `B != 1`
- `is_identity == 1` because `(0, 1)` matches `AffineCoordinates.identityElement`.
- `(on_curve | is_identity) != 0`, so no `error.InvalidEncoding` is returned.
- `ret.z.cMov(P384.identityElement.z, is_identity)` sets `z = 0`.
- The invalid decoded point becomes `P384.identityElement`.

Runtime reproduction confirmed:

```text
fromSec1 accepted; z=0
decoded point is rejected as: IdentityElement
```

## Why This Is A Real Bug

SEC1 uncompressed point decoding must validate that supplied affine coordinates lie on the curve. The SEC1 infinity encoding is separate: encoding type `0x00` with no coordinate payload.

Accepting `(x=0, y=1)` in an uncompressed `0x04` encoding conflates an invalid affine coordinate pair with the point at infinity. This causes the decoder to fail open and return a valid internal identity element for malformed attacker-controlled public-key input.

## Fix Requirement

`fromAffineCoordinates` must reject affine identity coordinates unless the caller is explicitly decoding the SEC1 infinity form.

For uncompressed SEC1 coordinates, validity must require `on_curve == 1`.

## Patch Rationale

The patch changes the validation condition from accepting either an on-curve point or the affine identity sentinel to accepting only on-curve points:

```diff
-        if ((on_curve | is_identity) == 0) {
+        if (on_curve == 0) {
             return error.InvalidEncoding;
         }
```

This preserves valid affine point decoding while preventing `(0, 1)` from bypassing curve membership validation.

The explicit SEC1 infinity path remains handled separately in `fromSec1` for encoding type `0x00`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/pcurves/p384.zig b/lib/std/crypto/pcurves/p384.zig
index 0dbfdc67f1..b9ff99e321 100644
--- a/lib/std/crypto/pcurves/p384.zig
+++ b/lib/std/crypto/pcurves/p384.zig
@@ -51,7 +51,7 @@ pub const P384 = struct {
         const yy = y.sq();
         const on_curve = @intFromBool(x3AxB.equivalent(yy));
         const is_identity = @intFromBool(x.equivalent(AffineCoordinates.identityElement.x)) & @intFromBool(y.equivalent(AffineCoordinates.identityElement.y));
-        if ((on_curve | is_identity) == 0) {
+        if (on_curve == 0) {
             return error.InvalidEncoding;
         }
         var ret = P384{ .x = x, .y = y, .z = Fe.one };
```