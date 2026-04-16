# Secret Exponent Enters Public Variable-Time Path

## Classification

Security control failure; high severity; side-channel exposure of secret exponent bits through variable-time finite-field exponentiation.

## Affected Locations

- `lib/std/crypto/ff.zig`
  - `powWithEncodedExponentInternal`
  - Reported location: `lib/std/crypto/ff.zig:632`
  - Patched condition location in provided source: near line `702`

## Summary

`powWithEncodedExponent()` is the secret-exponent API and calls `powWithEncodedExponentInternal(..., public=false)`. Due to missing parentheses in the short-exponent dispatch condition, some 3-byte secret exponents enter the public short-exponent path. That path branches on exponent bits and performs extra Montgomery multiplication/copy work only for set bits, causing exponent-dependent timing/work.

## Provenance

- Verified by Swival security analysis.
- Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)
- Confidence: certain.

## Preconditions

- Caller uses `powWithEncodedExponent()` for a secret exponent.
- Encoded exponent length is exactly 3 bytes.
- Most significant exponent byte is `<= 0x0f`.
- Exponent is nonzero, so it passes the null-exponent rejection.

## Proof

The vulnerable condition was:

```zig
if (public and e.len < 3 or (e.len == 3 and e[if (endian == .big) 0 else 2] <= 0b1111)) {
```

This parses as:

```zig
(public and e.len < 3) or (e.len == 3 and top_byte <= 0x0f)
```

Therefore, when `public == false`, the 3-byte case can still evaluate true.

That incorrectly selects the public short-exponent path:

```zig
const k: u1 = @truncate(b >> j);
if (k != 0) {
    const t = self.montgomeryMul(out, x_m);
    @memcpy(out.v.limbs(), t.v.limbsConst());
}
```

Each secret `1` bit performs an extra Montgomery multiplication and copy. Each secret `0` bit skips them. The secret-safe path is bypassed.

## Why This Is A Real Bug

The API contract distinguishes secret and public exponents:

- `powWithEncodedExponent()` is intended for secret exponents.
- `powWithEncodedPublicExponent()` is intended for public exponents.

`powWithEncodedExponent()` correctly passes `public=false`, but the malformed boolean expression allows a subset of secret exponents to enter a public variable-time path anyway. This violates the side-channel protection expected from the secret-exponent API.

The null-exponent check only rejects all-zero exponents and does not prevent the triggering nonzero 3-byte exponent case.

## Fix Requirement

Gate all short public-exponent cases behind `public == true`.

Specifically, the condition must require:

```zig
public and (short exponent condition)
```

not:

```zig
(public and first short condition) or second short condition
```

## Patch Rationale

The patch adds parentheses around the full short-exponent predicate:

```zig
if (public and (e.len < 3 or (e.len == 3 and e[if (endian == .big) 0 else 2] <= 0b1111))) {
```

This preserves the optimized public path for public short exponents while ensuring secret exponents always take the protected exponentiation path.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/ff.zig b/lib/std/crypto/ff.zig
index caae9cb33e..febcd3a461 100644
--- a/lib/std/crypto/ff.zig
+++ b/lib/std/crypto/ff.zig
@@ -702,7 +702,7 @@ pub fn Modulus(comptime max_bits: comptime_int) type {
             var out = self.one();
             self.toMontgomery(&out) catch unreachable;
 
-            if (public and e.len < 3 or (e.len == 3 and e[if (endian == .big) 0 else 2] <= 0b1111)) {
+            if (public and (e.len < 3 or (e.len == 3 and e[if (endian == .big) 0 else 2] <= 0b1111))) {
                 // Do not use a precomputation table for short, public exponents
                 var x_m = x;
                 if (!x.montgomery) {
```