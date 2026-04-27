# sticky bit computed from overwritten rlo

## Classification

Logic error, medium severity, confidence certain.

## Affected Locations

`library/compiler-builtins/libm/src/math/generic/fma.rs:76`

## Summary

`fma_round` shifts the product low word `rlo` when aligning `x * y` against a larger-magnitude `z`, then computes the sticky bit from the already overwritten `rlo`. This loses information from the original discarded low bits and can produce an incorrectly rounded fused multiply-add result.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `d > F::BITS`
- After subtracting `F::BITS`, the remaining `d` is in `1..F::BITS`
- Inputs are finite and nonzero
- `z` has sufficiently larger magnitude than `x * y`, so the branch that right-shifts the product is reached

## Proof

The reproduced `f64` fallback case satisfies the preconditions:

- `nx.e + ny.e = -106`
- `nz.e = 1`
- Initial `d = 107`
- After `d -= F::BITS`, remaining `d = 43`
- Original product low word has discarded bits: `old rlo = 0x000003d3d7e19ba8`
- Shifted replacement is zero: `new rlo pre-sticky = 0x0000000000000000`
- Current code computes sticky as `false`
- Correct computation from original `rlo` computes sticky as `true`

Observed result:

```rust
assert_eq!(got.to_bits(), 0x4350000000000000);
assert_eq!(expected.to_bits(), 0x4350000000000001);
```

The incorrect sticky bit causes the fallback implementation to round down to `0x4350000000000000`, while hardware fused `mul_add` and the corrected sticky computation return `0x4350000000000001`.

Reachability is practical because `library/compiler-builtins/libm/src/math/fma.rs:46` calls this generic `fma_round` for the `f64` fallback path, and `library/compiler-builtins/libm/src/math/arch/x86/fma.rs:129` also has an x86 fallback using it.

## Why This Is A Real Bug

A sticky bit represents whether any discarded bit was nonzero during alignment. In this branch, the discarded bits are in the original `rlo` before the right shift. The implementation overwrites `rlo` first:

```rust
rlo = (rhi << (sbits - d)) | (rlo >> d);
```

It then tests the overwritten value:

```rust
rlo |= IntTy::<F>::from((rlo << (sbits - d)) != zero);
```

That test no longer reflects the discarded low bits from the original product. The reproduced input demonstrates a concrete one-ulp rounding error in a reachable finite nonzero case.

## Fix Requirement

Preserve the original `rlo` before shifting and compute the sticky bit from that saved value.

## Patch Rationale

The patch stores `rlo` in `rlo_orig` before overwriting it, then computes sticky from `rlo_orig`:

```rust
let rlo_orig = rlo;
rlo = (rhi << (sbits - d)) | (rlo >> d);
rlo |= IntTy::<F>::from((rlo_orig << (sbits - d)) != zero);
```

This preserves the intended shifted product construction while restoring the sticky-bit source to the actual discarded low bits.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/libm/src/math/generic/fma.rs b/library/compiler-builtins/libm/src/math/generic/fma.rs
index aaf459d1b61..73817ac6ae5 100644
--- a/library/compiler-builtins/libm/src/math/generic/fma.rs
+++ b/library/compiler-builtins/libm/src/math/generic/fma.rs
@@ -71,9 +71,10 @@ pub fn fma_round<F>(x: F, y: F, z: F, _round: Round) -> FpResult<F>
                 // Exactly `sbits`, nothing to do
             } else if d < sbits {
                 // Remaining shift fits within `sbits`. Leave `z` in place, shift `x * y`
+                let rlo_orig = rlo;
                 rlo = (rhi << (sbits - d)) | (rlo >> d);
                 // Set the sticky bit
-                rlo |= IntTy::<F>::from((rlo << (sbits - d)) != zero);
+                rlo |= IntTy::<F>::from((rlo_orig << (sbits - d)) != zero);
                 rhi = rhi >> d;
             } else {
                 // `z`'s magnitude is enough that `x * y` is irrelevant. It was nonzero, so set
```