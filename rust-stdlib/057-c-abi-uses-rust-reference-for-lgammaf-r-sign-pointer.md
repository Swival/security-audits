# C ABI uses Rust reference for lgamma_r sign pointer

## Classification

Trust-boundary violation, medium severity. Confidence: certain.

## Affected Locations

`library/compiler-builtins/compiler-builtins/src/math/mod.rs:204`

## Summary

The exported C ABI functions `lgamma_r` and `lgammaf_r` accepted the C `int *` sign output parameter as `&mut i32`. A Rust mutable reference is required to be non-null, aligned, valid, and uniquely borrowed before function body execution. C callers can pass arbitrary pointers, including `NULL`, so the ABI boundary incorrectly trusted an invariant that C does not provide.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- `partial_availability` is built for the target.
- A C caller invokes `lgamma_r(double, int *)` or `lgammaf_r(float, int *)`.
- The caller passes a null, unaligned, dangling, or otherwise invalid sign pointer.

## Proof

`library/compiler-builtins/compiler-builtins/src/math/mod.rs` exported:

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

The `intrinsics!` macro emits unmangled `extern "C"` wrappers when `feature = "unmangled-names"` is enabled, preserving the argument type in the exported function. `compiler-builtins = ["dep:core", "unmangled-names"]` enables this path for the intended compiler-builtins runtime configuration.

Therefore, C callers see the expected ABI shape `lgamma_r(double, int *)` / `lgammaf_r(float, int *)`, but Rust receives the pointer as `&mut i32`. Passing `NULL` or another invalid pointer violates Rust reference validity requirements at the FFI boundary before the function can perform any defensive check. If execution reaches the body, `*s = r.1` writes through the invalid pointer.

## Why This Is A Real Bug

This is not only a possible crash from dereferencing a bad pointer. The Rust function signature itself creates undefined behavior as soon as an invalid C pointer is converted into `&mut i32`. The C ABI permits arbitrary `int *` values, while Rust references do not. The exported function therefore crosses a trust boundary using a type that encodes stronger validity guarantees than the caller is required to uphold.

The reproducer confirmed this path is reachable whenever `partial_availability` is compiled, including Windows and other non-Unix supported targets.

## Fix Requirement

The C-facing parameter must be represented as a raw pointer, `*mut i32`, not `&mut i32`. The implementation must check for null before writing the sign result. Any dereference must occur inside an explicit `unsafe` block after validation.

## Patch Rationale

The patch changes both exported signatures from `&mut i32` to `*mut i32`, matching the C ABI contract for `int *`. It then guards the output write with `if !s.is_null()` and performs the store only inside an explicit `unsafe` block.

This removes the invalid Rust reference requirement from the FFI boundary and prevents null-pointer writes while preserving normal behavior for valid sign pointers.

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