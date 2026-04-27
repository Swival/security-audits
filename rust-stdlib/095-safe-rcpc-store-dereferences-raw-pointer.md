# Safe RCpc Store Dereferences Raw Pointer

## Classification

- Type: vulnerability
- Severity: high
- Confidence: certain
- Impact: safe Rust can invoke undefined behavior through a safe AArch64 NEON RCpc store intrinsic

## Affected Locations

- `library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml:2051`
- Generated implementation evidence:
  - `library/stdarch/crates/core_arch/src/aarch64/neon/generated.rs:25504`
  - `library/stdarch/crates/core_arch/src/aarch64/neon/generated.rs:25507`
  - `library/stdarch/crates/core_arch/src/aarch64/neon/generated.rs:25454`
  - `library/stdarch/crates/core_arch/src/aarch64/neon/generated.rs:25456`

## Summary

The AArch64 NEON `vstl1` RCpc lane store intrinsics were declared safe while accepting raw mutable pointers. The generated safe wrapper casts the public pointer argument to `*mut AtomicI64` and dereferences it before calling `store`. Because the API did not require `unsafe`, callers could pass null, dangling, misaligned, aliasing, or non-atomic-compatible pointers from safe Rust and trigger undefined behavior.

## Provenance

- Source: Swival Security Scanner
- URL: https://swival.dev
- Reproduction status: reproduced
- Patch: `095-safe-rcpc-store-dereferences-raw-pointer.patch`

## Preconditions

- Caller is in a matching AArch64 target-feature context with `#[target_feature(enable = "neon,rcpc3")]`.
- Caller passes an invalid, misaligned, dangling, aliasing, or otherwise non-atomic-compatible pointer to a safe `vstl1` intrinsic.

## Proof

The source specification declares both `vstl1{neon_type[1].lane_nox}` entries as safe:

```yaml
safety: safe
```

The affected signed 64-bit implementation composes the raw pointer into an atomic pointer and dereferences it:

```yaml
- Let:
    - "atomic_dst"
    - "ptr as *mut crate::sync::atomic::AtomicI64"
...
- MethodCall:
  - "(*atomic_dst)"
  - store
  - [FnCall: [transmute, [lane]],"crate::sync::atomic::Ordering::Release"]
```

The reproduced generated code confirms the safe public function accepts `ptr` and then performs:

```rust
(*atomic_dst).store(...)
```

The `u64`, `f64`, and `p64` variants are also safe wrappers that forward to the same `s64` implementation after casting the pointer to `*mut i64`.

## Why This Is A Real Bug

Safe Rust functions may not require callers to uphold unchecked pointer validity, alignment, aliasing, or atomic-layout requirements. Here, those requirements are necessary because the implementation dereferences a raw pointer as `AtomicI64` and performs an atomic store. Target-feature gating and instability do not make arbitrary raw-pointer dereference safe. Therefore the intrinsic violates Rust's safety contract by allowing undefined behavior from safe Rust.

## Fix Requirement

The affected `vstl1` lane store intrinsics must be marked unsafe, or the implementation must avoid dereferencing arbitrary raw pointers in safe code. The unsafe contract must cover pointer validity, alignment, aliasing, and atomic-store compatibility.

## Patch Rationale

The patch changes both RCpc `vstl1{neon_type[1].lane_nox}` entries from `safety: safe` to:

```yaml
safety:
  unsafe: [neon]
```

This matches the existing convention for NEON memory intrinsics that impose caller-side pointer requirements. It moves the pointer validity obligation to an explicit unsafe call boundary and prevents safe Rust from reaching the raw-pointer dereference without acknowledging the contract.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml b/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
index a769d352649..c8d63fd771b 100644
--- a/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
+++ b/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
@@ -4459,7 +4459,8 @@ intrinsics:
     doc: "Store-Release a single-element structure from one lane of one register."
     arguments: ["ptr: {type[0]}", "val: {neon_type[1]}"]
     static_defs: ["const LANE: i32"]
-    safety: safe
+    safety:
+      unsafe: [neon]
     attr:
       - FnCall: [target_feature, ['enable = "neon,rcpc3"']]
       - FnCall: [cfg_attr, [{FnCall: [all, [test, {FnCall: [not, ['target_env= "msvc"']]}]]}, {FnCall: [assert_instr, [stl1, 'LANE = 0']]}]]
@@ -4488,7 +4489,8 @@ intrinsics:
     doc: "Store-Release a single-element structure from one lane of one register."
     arguments: ["ptr: {type[0]}", "val: {neon_type[1]}"]
     static_defs: ["const LANE: i32"]
-    safety: safe
+    safety:
+      unsafe: [neon]
     attr:
       - FnCall: [target_feature, ['enable = "neon,rcpc3"']]
       - FnCall: [cfg_attr, [{FnCall: [all, [test, {FnCall: [not, ['target_env= "msvc"']]}]]}, {FnCall: [assert_instr, [stl1, 'LANE = 0']]}]]
```