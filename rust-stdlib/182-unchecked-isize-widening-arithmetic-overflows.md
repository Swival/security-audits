# unchecked isize widening arithmetic overflows

## Classification

Invariant violation, medium severity, confidence certain.

## Affected Locations

`library/core/src/intrinsics/fallback.rs:28`

## Summary

The generic widening fallback for `CarryingMulAdd` instantiated `isize` with an unsigned double-width type. Negative `isize` operands were cast into the full unsigned domain before multiplication, so valid signed inputs such as `-1isize * -1isize` could overflow the selected double-width unsigned type instead of performing signed double-width arithmetic.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`isize::carrying_mul_add` is called through the fallback implementation with a negative `self` or negative multiplicand.

## Proof

The `impl_carrying_mul_add_by_widening!` macro computes:

```rust
let wide = (self as $w) * (a as $w) + (b as $w) + (c as $w);
```

For `isize`, the macro previously used:

```rust
isize usize UDoubleSize,
```

On a 64-bit target, `UDoubleSize` is `u128`. A negative `isize` cast to `u128` maps into the unsigned domain; for example:

```rust
-1isize as u128 == u128::MAX
```

Therefore:

```rust
CarryingMulAdd::carrying_mul_add(-1isize, -1isize, 0, 0)
```

reaches:

```rust
u128::MAX * u128::MAX
```

inside the fallback body. That multiplication overflows `u128`, even though the signed double-width product of `-1 * -1` is representable and should produce low word `1` and high word `0`.

Reachability is real because the fallback trait is public/exported for testing, `core::intrinsics::carrying_mul_add` delegates to the fallback, and integer wrapper methods delegate to that intrinsic.

## Why This Is A Real Bug

The fallback is intended to compute multiply-add in a widened type so the intermediate arithmetic is possible without overflow. For signed fixed-width types, the macro already uses signed double-width types (`i8 -> i16`, `i16 -> i32`, `i32 -> i64`, `i64 -> i128`). `isize` was the inconsistent case: it used `UDoubleSize`.

This violates the widening invariant for valid signed inputs. In checked execution the fallback can panic on overflowing arithmetic; in unchecked execution it relies on wrapping behavior in a code path whose correctness depends on non-overflowing widened arithmetic.

## Fix Requirement

Use a signed double-width type for the `isize` fallback, matching the signed integer implementations.

## Patch Rationale

The patch changes the `isize` macro instantiation from `UDoubleSize` to `SDoubleSize` and defines `SDoubleSize` per pointer width:

```rust
#[cfg(target_pointer_width = "16")]
type SDoubleSize = i32;
#[cfg(target_pointer_width = "32")]
type SDoubleSize = i64;
#[cfg(target_pointer_width = "64")]
type SDoubleSize = i128;
```

This preserves the existing macro structure while making `isize` arithmetic consistent with the other signed integer types. Negative operands are sign-extended into a signed double-width type before multiplication, so products such as `-1 * -1` remain representable and do not overflow the widened intermediate.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/intrinsics/fallback.rs b/library/core/src/intrinsics/fallback.rs
index aa9033ee3d2..b8a0556920b 100644
--- a/library/core/src/intrinsics/fallback.rs
+++ b/library/core/src/intrinsics/fallback.rs
@@ -41,7 +41,7 @@ fn carrying_mul_add(self, a: Self, b: Self, c: Self) -> ($u, $t) {
     i16 u16 i32,
     i32 u32 i64,
     i64 u64 i128,
-    isize usize UDoubleSize,
+    isize usize SDoubleSize,
 }
 
 #[cfg(target_pointer_width = "16")]
@@ -50,6 +50,12 @@ fn carrying_mul_add(self, a: Self, b: Self, c: Self) -> ($u, $t) {
 type UDoubleSize = u64;
 #[cfg(target_pointer_width = "64")]
 type UDoubleSize = u128;
+#[cfg(target_pointer_width = "16")]
+type SDoubleSize = i32;
+#[cfg(target_pointer_width = "32")]
+type SDoubleSize = i64;
+#[cfg(target_pointer_width = "64")]
+type SDoubleSize = i128;
 
 #[inline]
 const fn wide_mul_u128(a: u128, b: u128) -> (u128, u128) {
```