# unchecked MTE tag offset

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`library/stdarch/crates/core_arch/src/aarch64/mte.rs:54`

## Summary

`__arm_mte_increment_tag` documents `OFFSET` as a compile-time constant in `[0, 15]`, but passed the caller-supplied const generic directly to LLVM intrinsic `llvm.aarch64.addg` without enforcing that range. Invalid values such as `16` propagated into backend code generation and caused an LLVM selection failure instead of a Rust-side compile-time diagnostic.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller instantiates public unsafe wrapper `__arm_mte_increment_tag`.
- Caller supplies const generic `OFFSET` outside `0..=15`, for example `__arm_mte_increment_tag::<16, _>(p)`.
- Target compilation reaches AArch64 MTE intrinsic lowering.

## Proof

The affected function accepted `OFFSET` as a const generic and called:

```rust
addg_(src as *const (), OFFSET) as *const T
```

There was no `static_assert_range!`, `static_assert_uimm_bits!`, or equivalent validation before the call.

The reproducer confirmed:

- `OFFSET = 16` reaches LLVM IR as `call ptr @llvm.aarch64.addg(ptr %src, i64 16)`.
- Lowering then fails with `rustc-LLVM ERROR: Cannot select: intrinsic %llvm.aarch64.addg`.
- The same test with `OFFSET = 15` compiles and emits valid assembly: `addg x0, x0, #0, #15`.
- Other stdarch const-immediate wrappers validate ranges, for example `library/stdarch/crates/core_arch/src/aarch64/prefetch.rs:77` uses `static_assert_uimm_bits!`.

## Why This Is A Real Bug

The wrapper’s public contract requires `OFFSET` to be in `[0, 15]`, matching the valid immediate range for the AArch64 MTE `addg` operation. Because the wrapper did not enforce that contract, invalid caller-controlled const generics escaped Rust-level validation and triggered a backend codegen failure. This is a concrete validation gap with reproduced compiler failure behavior, not just a documentation mismatch.

## Fix Requirement

Enforce `OFFSET` in `0..=15` before calling `addg_`, producing a Rust-side compile-time diagnostic for invalid const generic values.

## Patch Rationale

The patch adds:

```rust
static_assert_range!(OFFSET, 0..=15);
```

inside `__arm_mte_increment_tag` immediately before the intrinsic call. This matches the documented range, prevents invalid immediates from reaching `llvm.aarch64.addg`, and follows the existing stdarch pattern for validating const-immediate intrinsic arguments.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/core_arch/src/aarch64/mte.rs b/library/stdarch/crates/core_arch/src/aarch64/mte.rs
index a5031a45c1a..bde88c2125d 100644
--- a/library/stdarch/crates/core_arch/src/aarch64/mte.rs
+++ b/library/stdarch/crates/core_arch/src/aarch64/mte.rs
@@ -51,6 +51,7 @@ pub unsafe fn __arm_mte_create_random_tag<T>(src: *const T, mask: u64) -> *const
 #[target_feature(enable = "mte")]
 #[unstable(feature = "stdarch_aarch64_mte", issue = "129010")]
 pub unsafe fn __arm_mte_increment_tag<const OFFSET: i64, T>(src: *const T) -> *const T {
+    static_assert_range!(OFFSET, 0..=15);
     addg_(src as *const (), OFFSET) as *const T
 }
```