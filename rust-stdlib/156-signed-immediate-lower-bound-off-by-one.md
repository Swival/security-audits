# signed immediate lower bound off by one

## Classification

validation gap, medium severity, confidence certain

## Affected Locations

`library/stdarch/crates/core_arch/src/macros.rs:56`

## Summary

`static_assert_simm_bits!` accepted one value below the valid signed immediate range. For an N-bit signed immediate, the valid lower bound is `-2^(N-1)`, but the macro checked `-2^(N-1)-1 <= imm`, allowing exactly one invalid boundary value.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A signed-immediate intrinsic wrapper invokes `static_assert_simm_bits!` with a compile-time immediate below the representable signed range by exactly one.

## Proof

The macro validated signed immediates with:

```rust
(-1 << ($bits - 1)) - 1 <= $imm && $imm < (1 << ($bits - 1))
```

For a 5-bit signed immediate, the valid range is `-16..=15`. The expression above instead permits `-17..=15`.

Reproduction confirmed that `IMM_S5 = -17` reaches `__lsx_vmaxi_b` at `library/stdarch/crates/core_arch/src/loongarch64/lsx/generated.rs:2130`. That wrapper targets LLVM intrinsic `llvm.loongarch.lsx.vmaxi.b`, declared at `library/stdarch/crates/core_arch/src/loongarch64/lsx/generated.rs:182`, whose generator header operand is `si5` at `library/stdarch/crates/stdarch-gen-loongarch/lsxintrin.h:611`.

Equivalent boundary behavior was also confirmed on an installed committed `stdarch` path: `vec_splat_s8::<-17>()` compiles for `powerpc64le-unknown-linux-gnu`, while `vec_splat_s8::<-18>()` fails with `IMM5 doesn't fit in 5 bits`.

Analogous invalid accepted boundary values include `-129` for `simm8` and `-2049` for `simm12`.

## Why This Is A Real Bug

The macro is intended to reject signed immediates outside the representable N-bit range before they reach target intrinsic wrappers. The lower-bound expression is mathematically incorrect by one, so invalid immediates are accepted by Rust-side validation and can be passed to target-specific LLVM intrinsic paths that declare stricter signed immediate operands.

## Fix Requirement

Remove the extra `- 1` from the signed lower-bound expression so the accepted range is exactly:

```rust
-2^(bits - 1) <= imm < 2^(bits - 1)
```

## Patch Rationale

The patch changes only the lower-bound check:

```diff
-            (-1 << ($bits - 1)) - 1 <= $imm && $imm < (1 << ($bits - 1)),
+            (-1 << ($bits - 1)) <= $imm && $imm < (1 << ($bits - 1)),
```

This preserves the existing exclusive upper bound and corrects the inclusive lower bound to match the representable signed immediate range.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/core_arch/src/macros.rs b/library/stdarch/crates/core_arch/src/macros.rs
index 83039bc65ac..9b9306a4981 100644
--- a/library/stdarch/crates/core_arch/src/macros.rs
+++ b/library/stdarch/crates/core_arch/src/macros.rs
@@ -53,7 +53,7 @@ macro_rules! static_assert_uimm_bits {
 macro_rules! static_assert_simm_bits {
     ($imm:ident, $bits:expr) => {
         static_assert!(
-            (-1 << ($bits - 1)) - 1 <= $imm && $imm < (1 << ($bits - 1)),
+            (-1 << ($bits - 1)) <= $imm && $imm < (1 << ($bits - 1)),
             concat!(
                 stringify!($imm),
                 " doesn't fit in ",
```