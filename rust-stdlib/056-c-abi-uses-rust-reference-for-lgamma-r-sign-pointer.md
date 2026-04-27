# C ABI uses Rust reference for lgamma_r sign pointer

## Classification

Trust-boundary violation, medium severity. Confidence: certain.

## Affected Locations

- `library/compiler-builtins/compiler-builtins/src/math/mod.rs:198`
- `library/compiler-builtins/compiler-builtins/src/math/mod.rs:205`

## Summary

`lgamma_r` and `lgammaf_r` expose C ABI symbols that accept the sign output parameter as `&mut i32`. A Rust mutable reference is not a C pointer type: it must already be non-null, aligned, valid, and exclusive when the function is entered. C callers can pass arbitrary `int *` values, including null or invalid pointers, crossing the FFI boundary into immediate Rust undefined behavior before the function body can safely execute.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The affected `partial_availability` math symbols are built for the target.
- The C ABI symbol is exposed through the compiler-builtins unmangled wrapper configuration.
- A C caller passes a null or invalid sign pointer to `lgamma_r` or `lgammaf_r`.

## Proof

The affected source defines:

```rust
pub extern "C" fn lgamma_r(x: f64, s: &mut i32) -> f64 {
    let r = super::libm_math::lgamma_r(x);
    *s = r.1;
    r.0
}

pub extern "C" fn lgammaf_r(x: f32, s: &mut i32) -> f32 {
    let r = super::libm_math::lgammaf_r(x);
    *s = r.1;
    r.0
}
```

The reproducer confirmed that:

- `library/compiler-builtins/compiler-builtins/src/math/mod.rs:199` exposes `lgamma_r(x: f64, s: &mut i32)`.
- `library/compiler-builtins/compiler-builtins/src/math/mod.rs:205` exposes `lgammaf_r(x: f32, s: &mut i32)`.
- `library/compiler-builtins/compiler-builtins/src/macros.rs:473` emits an unmangled C ABI wrapper when `unmangled-names` is enabled.
- `library/compiler-builtins/compiler-builtins/Cargo.toml:49` enables that behavior through the `compiler-builtins` feature.

A C caller can therefore reach a Rust `&mut i32` parameter. Passing null or an invalid pointer violates Rust reference validity requirements at the ABI boundary. The function then writes through the parameter with `*s = r.1`, which typically crashes for null or invalid memory and can write four bytes to an unintended writable address.

## Why This Is A Real Bug

C ABI functions must model C pointer semantics at the boundary. `lgamma_r` and `lgammaf_r` take an output `int *`-style sign pointer, but the implementation used `&mut i32`, which imposes stronger Rust-only validity and exclusivity guarantees on untrusted C input. Those guarantees cannot be assumed for an externally supplied pointer.

This is not only a bad pointer dereference in the function body. The undefined behavior exists as soon as Rust receives an invalid value for a reference-typed parameter. Using `&mut i32` across this FFI boundary therefore makes ordinary malformed C input capable of triggering Rust UB.

## Fix Requirement

Use a raw C-compatible pointer type for the sign output parameter, validate it before writing, and preserve the C ABI behavior for valid callers.

## Patch Rationale

The patch changes both sign parameters from `&mut i32` to `*mut i32`, matching C ABI pointer semantics. It then checks `!s.is_null()` before writing the sign result.

This removes the invalid Rust reference from the FFI boundary. Valid callers still receive the computed sign value, while null callers no longer create immediate Rust reference UB or a null dereference.

## Residual Risk

None

## Patch

```diff
diff --git a/library/compiler-builtins/compiler-builtins/src/math/mod.rs b/library/compiler-builtins/compiler-builtins/src/math/mod.rs
index 3dfa3863bb7..6af406b4ab5 100644
--- a/library/compiler-builtins/compiler-builtins/src/math/mod.rs
+++ b/library/compiler-builtins/compiler-builtins/src/math/mod.rs
@@ -196,15 +196,19 @@ pub mod partial_availability {
 
     // allow for windows (and other targets)
     intrinsics! {
-        pub extern "C" fn lgamma_r(x: f64, s: &mut i32) -> f64 {
+        pub extern "C" fn lgamma_r(x: f64, s: *mut i32) -> f64 {
             let r = super::libm_math::lgamma_r(x);
-            *s = r.1;
+            if !s.is_null() {
+                unsafe { *s = r.1 };
+            }
             r.0
         }
 
-        pub extern "C" fn lgammaf_r(x: f32, s: &mut i32) -> f32 {
+        pub extern "C" fn lgammaf_r(x: f32, s: *mut i32) -> f32 {
             let r = super::libm_math::lgammaf_r(x);
-            *s = r.1;
+            if !s.is_null() {
+                unsafe { *s = r.1 };
+            }
             r.0
         }
     }
```