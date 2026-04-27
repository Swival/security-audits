# unchecked exponent digit accumulation

## Classification

Validation gap, medium severity, confirmed.

## Affected Locations

`library/compiler-builtins/libm/src/math/support/hex_float.rs:295`

## Summary

`parse_hex` accumulates decimal exponent digits into `pexp: u32` using saturating multiplication followed by unchecked addition. For exponent strings larger than `u32::MAX`, the multiplication may saturate to `u32::MAX`, after which adding the next digit overflows in debug/const contexts and wraps in release builds.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller parses a finite hexadecimal float whose decimal exponent exceeds `u32::MAX`, for example:

```rust
libm::support::hf32("0x1p4294967296")
```

The path is reachable through `hf32`, `hf64`, and `parse_any`.

## Proof

Exponent digits originate from the input string in `parse_any` and reach `parse_hex` unchanged:

`hf32` / `hf64` -> `parse_hex_exact` -> `parse_any` -> `parse_finite` -> `parse_hex`

In `parse_hex`:

- `library/compiler-builtins/libm/src/math/support/hex_float.rs:286` initializes `pexp: u32`
- `library/compiler-builtins/libm/src/math/support/hex_float.rs:294` applies `pexp = pexp.saturating_mul(10)`
- `library/compiler-builtins/libm/src/math/support/hex_float.rs:295` applies unchecked `pexp += digit as u32`

For input `0x1p4294967296`, accumulation reaches `pexp = 4294967290`; adding digit `6` overflows `u32`.

Runtime evidence confirms:

- Debug build panics at `hex_float.rs:295` with `attempt to add with overflow`
- Release build wraps the accumulator and misparses `0x1p4294967296` as `1.0` (`0x3f800000`) instead of treating it as a huge overflowing value

## Why This Is A Real Bug

The parser already attempts saturating exponent accumulation with `saturating_mul(10)`, so unchecked addition contradicts the intended overflow handling. The behavior is externally reachable from public parsing helpers and causes observable incorrect behavior:

- Debug/const evaluation can panic on valid-shaped finite hex-float input
- Release builds can silently wrap the exponent accumulator
- The wrapped exponent can produce a materially wrong parsed value

## Fix Requirement

Exponent digit accumulation must not overflow. The addition after multiplying by ten must be saturating or checked consistently with the existing saturating multiplication.

## Patch Rationale

The patch changes:

```rust
pexp += digit as u32;
```

to:

```rust
pexp = pexp.saturating_add(digit as u32);
```

This preserves the existing design of saturating exponent accumulation. Once the exponent exceeds `u32::MAX`, `pexp` remains clamped at `u32::MAX`, allowing the later `saturating_add_unsigned` or `saturating_sub_unsigned` on `exp` to classify the parsed value as huge or tiny instead of panicking or wrapping.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/libm/src/math/support/hex_float.rs b/library/compiler-builtins/libm/src/math/support/hex_float.rs
index e1100a4a119..c0af0c379a6 100644
--- a/library/compiler-builtins/libm/src/math/support/hex_float.rs
+++ b/library/compiler-builtins/libm/src/math/support/hex_float.rs
@@ -292,7 +292,7 @@ const fn parse_hex(mut b: &[u8]) -> Result<Parsed, HexFloatParseError> {
         };
         some_digits = true;
         pexp = pexp.saturating_mul(10);
-        pexp += digit as u32;
+        pexp = pexp.saturating_add(digit as u32);
     }
 
     if !some_digits {
```