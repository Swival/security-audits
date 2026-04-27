# Unencoded VSX Store Length

## Classification

Logic error, medium severity.

Confidence: certain.

## Affected Locations

- `library/stdarch/crates/core_arch/src/powerpc64/vsx.rs:87`

## Summary

`vec_xst_len` passed the public byte length directly to the `llvm.ppc.vsx.stxvl` intrinsic. The surrounding VSX wrappers show that this intrinsic expects the length encoded as `l << 56`, so any nonzero store length was supplied in the wrong bits and produced an incorrect VSX store length.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Caller uses `vec_xst_len` with any nonzero length.

## Proof

- `vec_xst_len` reaches the `impl_stores::vec_xst_len` implementation in `library/stdarch/crates/core_arch/src/powerpc64/vsx.rs`.
- The load helper encodes the length before calling the LLVM intrinsic:
  - `vec_lxvl(p, l)` calls `lxvl(p, l << 56)`.
- The store helper also encodes the length before calling the LLVM intrinsic:
  - `vec_stxvl(v, a, l)` calls `stxvl(v, a, l << 56)`.
- The affected store implementation bypassed `vec_stxvl` and called:
  - `stxvl(transmute(self), a as *mut u8, l)`
- Therefore a normal length such as `16` reached the intrinsic as `16`, not `16 << 56`.
- Reproduction confirmed generated code for `vec_xst_len(v, p, 16)` emitted an LLVM call with `i64 16` and assembly using `li 3, 16; stxvl ...`, proving the raw unencoded value was used.

## Why This Is A Real Bug

The public API documents `vec_xst_len` as storing between 0 and 16 bytes based on the supplied length. However, the LLVM VSX `stxvl` intrinsic expects the length in encoded form. Passing the raw public byte count places the count in the wrong byte, so the hardware instruction observes the wrong length.

This breaks partial and full vector stores through `vec_xst_len` for nonzero lengths.

## Fix Requirement

The store path must encode the length before calling `stxvl`, either by:

- calling the existing `vec_stxvl` helper, or
- passing `l << 56` directly to `stxvl`.

## Patch Rationale

The patch changes `impl_stores::vec_xst_len` to call `vec_stxvl` instead of calling `stxvl` directly.

This reuses the existing store wrapper that already performs the required `l << 56` encoding and keeps store behavior consistent with the load-side `vec_lxvl` wrapper.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/core_arch/src/powerpc64/vsx.rs b/library/stdarch/crates/core_arch/src/powerpc64/vsx.rs
index 7b42be8653c..96d8b6e43c4 100644
--- a/library/stdarch/crates/core_arch/src/powerpc64/vsx.rs
+++ b/library/stdarch/crates/core_arch/src/powerpc64/vsx.rs
@@ -84,7 +84,7 @@ impl VectorXstores for t_t_l!($ty) {
                 #[inline]
                 #[target_feature(enable = "power9-vector")]
                 unsafe fn vec_xst_len(self, a: Self::Out, l: usize) {
-                    stxvl(transmute(self), a as *mut u8, l)
+                    vec_stxvl(transmute(self), a as *mut u8, l)
                 }
             }
         };
```