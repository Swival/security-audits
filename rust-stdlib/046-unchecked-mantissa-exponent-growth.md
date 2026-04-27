# Unchecked Mantissa Exponent Growth

## Classification

Validation gap, low severity, confidence: certain.

## Affected Locations

`library/compiler-builtins/libm/src/math/support/hex_float.rs:257`

## Summary

`parse_hex` increments an `i32` exponent by 4 for every significant hexadecimal digit after the 128-bit significand buffer is full. That increment was unchecked. A hex float with more than 536M significant digits can overflow `exp`, causing a debug/const-eval panic or wrapped exponent semantics instead of a structured `HexFloatParseError`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller supplies a hexadecimal float string with over 536M significant digits.
- The input reaches `parse_hex` through `parse_any` / `parse_finite`, or through exact helper wrappers such as `hf32`, `hf64`, or `hf128` where exposed.
- The input has enough nonzero significant digits to fill `sig`, so subsequent digits take the overflow-prone branch.

## Proof

The parser accepts finite hexadecimal floats through `parse_any`, dispatches `0x` inputs to `parse_finite`, and then calls `parse_hex`.

Inside `parse_hex`, once `sig` is full:

```rust
} else {
    // FIXME: it is technically possible for exp to overflow if parsing a string with >500M digits
    exp += 4;
    inexact |= digit != 0;
}
```

After the first 32 nonzero hex digits fill `sig`, each further significant hex digit executes `exp += 4`. After `536_870_912` extra digits, `exp` advances from `2_147_483_644` to `2_147_483_648`, overflowing `i32`.

Observed effect:

- With overflow checks enabled, or in const-eval contexts, parsing panics/errors instead of returning `HexFloatParseError`.
- With overflow checks disabled, `exp` wraps to `i32::MIN`.
- Wrapped `exp` is later interpreted by `parse_finite` as extreme underflow, so exact helpers can report “the value is too tiny” for a mathematically huge input.

## Why This Is A Real Bug

The source already documents the condition with a FIXME, and the arithmetic violates the parser’s own exponent invariant by allowing an unchecked `i32` overflow. The affected path is reachable from parser entry points when sufficiently long hex float input is supplied. The resulting behavior is not just rejection of pathological input: it can panic in checked contexts or misclassify a huge value as tiny after wrapping.

## Fix Requirement

Replace the unchecked exponent growth with checked arithmetic and return a range parse error when adding 4 would overflow.

## Patch Rationale

The patch uses `checked_add(4)` at the only known unbounded positive mantissa-growth site. On overflow, it returns `HexFloatParseError("the value is too huge")`, matching the mathematical meaning of positive exponent overflow and the existing exact-parser error vocabulary.

This preserves normal parsing behavior and converts the pathological overflow case into an explicit range error.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/libm/src/math/support/hex_float.rs b/library/compiler-builtins/libm/src/math/support/hex_float.rs
index e1100a4a119..03c6d37f3b2 100644
--- a/library/compiler-builtins/libm/src/math/support/hex_float.rs
+++ b/library/compiler-builtins/libm/src/math/support/hex_float.rs
@@ -253,8 +253,10 @@ const fn parse_hex(mut b: &[u8]) -> Result<Parsed, HexFloatParseError> {
                     sig <<= 4;
                     sig |= digit as u128;
                 } else {
-                    // FIXME: it is technically possible for exp to overflow if parsing a string with >500M digits
-                    exp += 4;
+                    exp = match exp.checked_add(4) {
+                        Some(exp) => exp,
+                        None => return Err(HexFloatParseError("the value is too huge")),
+                    };
                     inexact |= digit != 0;
                 }
                 // Up until the fractional point, the value grows
```