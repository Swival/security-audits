# Out-of-Range SIMD Insert Index

## Classification

Invariant violation, medium severity, confidence certain.

## Affected Locations

`library/stdarch/crates/core_arch/src/powerpc/altivec.rs:470`

## Summary

The PowerPC AltiVec `vec_insert` implementation computes the lane index with bitwise `&` instead of modulo. For byte vectors, caller-controlled `IDX = 16` becomes lane `16`, which is outside the valid `0..15` range for a 16-lane SIMD vector. The public API documents modulo semantics, so `IDX = 16` should wrap to lane `0`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller invokes public `vec_insert` on an `i8` or `u8` AltiVec vector with const index `IDX = 16`, for example:

```rust
unsafe {
    vec_insert::<vector_unsigned_char, 16>(v, 1u8);
    vec_insert::<vector_signed_char, 16>(v, 1i8);
}
```

## Proof

`idx_in_vec` computed:

```rust
IDX & (16 / crate::mem::size_of::<T>() as u32)
```

For `T = i8` or `T = u8`, `size_of::<T>() == 1`, so `16 / 1 == 16`.

With `IDX = 16`:

```text
16 & 16 == 16
```

That value reaches:

```rust
simd_insert(self, const { idx_in_vec::<Self::Scalar, IDX>() }, s)
```

A 16-lane byte vector only accepts lane indices `0..15`. Therefore `simd_insert` receives out-of-range lane `16`.

## Why This Is A Real Bug

Rust SIMD intrinsic handling requires the constant index passed to `simd_insert` to be less than the vector length. The compiler codegen path rejects `idx >= in_len` as `SimdIndexOutOfBounds`, and const-eval treats the same condition as UB.

The public `vec_insert` documentation states that out-of-range indices use modulo arithmetic over the number of vector elements. For 16 byte elements, `IDX = 16` must resolve to lane `0`, not lane `16`.

## Fix Requirement

Compute the lane with modulo by element count:

```rust
IDX % (16 / crate::mem::size_of::<T>() as u32)
```

Do not use bitwise `&` for wrapping. `&` only matches modulo for masks of the form `2^n - 1`; the existing divisor is the element count itself, not such a mask.

## Patch Rationale

The patch replaces the incorrect bitwise operation with the documented modulo operation. This ensures every supported vector element type maps any `IDX` into the valid SIMD lane range:

- byte vectors: `IDX % 16`, valid `0..15`
- halfword vectors: `IDX % 8`, valid `0..7`
- word and float vectors: `IDX % 4`, valid `0..3`

The same helper is used by `vec_extract`, so the change also aligns extraction with the documented modulo semantics.

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