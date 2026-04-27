# Safe Typed RCpc Stores Erase Pointer Type

## Classification

High severity vulnerability.

Confidence: certain.

## Affected Locations

`library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml:4488`

## Summary

The safe typed `vstl1*_lane_*` RCpc store wrappers for `*mut u64`, `*mut f64`, and `*mut p64` erase the destination pointer type to `*mut i64` and call the signed `i64` implementation. The signed implementation casts the pointer to `*mut AtomicI64`, dereferences it, and performs a Release atomic store. This lets safe Rust trigger an unchecked raw-pointer dereference and an atomic `i64` write through non-`i64` destinations.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A safe caller uses an available `vstl1*_lane_*` overload for a `u64`, `f64`, or `p64` pointer on `aarch64` with `target_has_atomic = "64"` and `neon,rcpc3` enabled.

## Proof

The spec marks the typed wrapper block as safe:

```yaml
name: "vstl1{neon_type[1].lane_nox}"
arguments: ["ptr: {type[0]}", "val: {neon_type[1]}"]
safety: safe
types:
  - ['*mut u64', uint64x1_t, 'static_assert!', 'LANE == 0','']
  - ['*mut f64', float64x1_t,'static_assert!', 'LANE == 0','']
  - ['*mut p64', poly64x1_t, 'static_assert!', 'LANE == 0','']
  - ['*mut u64', uint64x2_t ,'static_assert_uimm_bits!', 'LANE, 1','q']
  - ['*mut f64', float64x2_t,'static_assert_uimm_bits!', 'LANE, 1','q']
  - ['*mut p64', poly64x2_t ,'static_assert_uimm_bits!', 'LANE, 1','q']
compose:
  - FnCall:
    - "vstl1{type[4]}_lane_s64::<LANE>"
    - - "ptr as *mut i64"
      - FnCall: [transmute, [val]]
```

The called signed implementation casts and dereferences the erased pointer as an `AtomicI64`:

```yaml
Let:
  - "atomic_dst"
  - "ptr as *mut crate::sync::atomic::AtomicI64"
MethodCall:
  - "(*atomic_dst)"
  - store
  - [FnCall: [transmute, [lane]], "crate::sync::atomic::Ordering::Release"]
```

The generated code path was reproduced at `library/stdarch/crates/core_arch/src/aarch64/neon/generated.rs:25504`, where the caller-provided raw pointer is dereferenced through `(*atomic_dst).store(...)`.

## Why This Is A Real Bug

Safe Rust cannot require callers to uphold pointer validity, alignment, atomic-access, or pointee-type invariants unless the function is `unsafe` and documents those requirements. These APIs accepted arbitrary raw pointers in safe functions, so safe code could pass null, dangling, misaligned, or otherwise invalid `*mut f64`, `*mut u64`, or `*mut p64` pointers and cause UB or a crash inside the implementation. The implementation also performs an atomic `i64` store through non-`i64` typed destinations after pointer type erasure.

## Fix Requirement

The typed RCpc store wrappers must not remain safe while they dereference caller-provided raw pointers and perform atomic stores through erased pointer types. They must either be marked `unsafe` or be reimplemented with correctly typed, contract-preserving storage semantics for each pointee type.

## Patch Rationale

The patch marks the typed wrapper block as unsafe:

```yaml
safety:
  unsafe: [neon]
```

This moves the raw-pointer and atomic-store validity obligations back to the caller, matching the implementation’s unchecked dereference and preventing safe Rust from invoking the UB-triggering path without an unsafe boundary.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml b/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
index a769d352649..eda658fee25 100644
--- a/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
+++ b/library/stdarch/crates/stdarch-gen-arm/spec/neon/aarch64.spec.yml
@@ -4488,7 +4488,8 @@ intrinsics:
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