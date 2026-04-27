# Out-of-Range SIMD Extract Index

## Classification

Invariant violation, medium severity.

Confidence: certain.

## Affected Locations

`library/stdarch/crates/core_arch/src/powerpc/altivec.rs:459`

`library/stdarch/crates/core_arch/src/powerpc/altivec.rs:498`

`library/stdarch/crates/core_arch/src/powerpc/altivec.rs:499`

## Summary

`vec_extract::<_, IDX>` documents modulo indexing, but the shared helper `idx_in_vec` used bitwise `&` with the lane count instead of modulo. For `i8` and `u8` AltiVec vectors, `IDX == 16` produces lane index `16`, which is outside the valid `0..15` SIMD lane range and violates the `simd_extract` intrinsic invariant.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A caller instantiates public `vec_extract::<_, 16>(...)` on `vector_signed_char` or `vector_unsigned_char`.

## Proof

`vec_extract` delegates to `a.vec_extract::<IDX>()`.

The `impl_vec_extract! { i8 }` and `impl_vec_extract! { u8 }` implementations call:

```rust
simd_extract(self, const { idx_in_vec::<Self::Scalar, IDX>() })
```

Before the patch, `idx_in_vec` computed:

```rust
IDX & (16 / crate::mem::size_of::<T>() as u32)
```

For `T == i8` or `T == u8`, the lane count is `16`, so `IDX == 16` computes `16 & 16 == 16`.

Valid lanes for a 16-lane byte vector are `0..15`. Therefore `simd_extract(self, 16)` receives an out-of-range lane index. A minimal equivalent `simd_extract(v16u8, 16)` is rejected by rustc with:

```text
invalid monomorphization of simd_extract intrinsic: SIMD index #1 is out of bounds (limit 16)
```

## Why This Is A Real Bug

The public `vec_extract` documentation states that the selected element is `b modulo the number of elements of a`. For 16-lane byte vectors, index `16` must select lane `0`.

The implementation instead produces index `16`, which is not a valid lane and violates the intrinsic's compile-time lane-index invariant. This is reachable through the public API with the stated preconditions.

## Fix Requirement

Compute the index modulo the number of lanes:

```rust
IDX % lane_count
```

Equivalently, for power-of-two lane counts, `IDX & (lane_count - 1)` would also be valid. The implemented fix uses direct modulo, matching the documented behavior.

## Patch Rationale

The patch changes the shared helper from masking with the lane count to modulo by the lane count:

```diff
-        IDX & (16 / crate::mem::size_of::<T>() as u32)
+        IDX % (16 / crate::mem::size_of::<T>() as u32)
```

This guarantees the computed lane is always in `0..lane_count` for all supported element widths. It also fixes both `vec_extract` and `vec_insert`, since both use `idx_in_vec` and both document modulo behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/core_arch/src/powerpc/altivec.rs b/library/stdarch/crates/core_arch/src/powerpc/altivec.rs
index 78ec39f91ff..1d9a83ff9ae 100644
--- a/library/stdarch/crates/core_arch/src/powerpc/altivec.rs
+++ b/library/stdarch/crates/core_arch/src/powerpc/altivec.rs
@@ -457,7 +457,7 @@ pub trait VectorInsert {
     }
 
     const fn idx_in_vec<T, const IDX: u32>() -> u32 {
-        IDX & (16 / crate::mem::size_of::<T>() as u32)
+        IDX % (16 / crate::mem::size_of::<T>() as u32)
     }
 
     macro_rules! impl_vec_insert {
```