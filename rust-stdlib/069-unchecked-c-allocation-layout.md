# Unchecked C Allocation Layout

## Classification

- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations

- `library/std/src/sys/alloc/sgx.rs:85`
- `library/std/src/sys/alloc/sgx.rs:91`

## Summary

The SGX C allocation shims `__rust_c_alloc` and `__rust_c_dealloc` accepted raw C ABI `size` and `align` parameters and passed them directly to `Layout::from_size_align_unchecked`.

Invalid external inputs could violate `Layout` invariants before allocator code was reached, creating undefined behavior or an enclave-local abort/DoS when runtime UB checks are enabled.

## Provenance

- Found by Swival Security Scanner: https://swival.dev
- Reproduced manually from the exported SGX allocation shim behavior and `Layout` invariant requirements.
- Patched in `069-unchecked-c-allocation-layout.patch`.

## Preconditions

- A C or native caller can reach the exported SGX symbols `__rust_c_alloc` or `__rust_c_dealloc`.
- The caller supplies an invalid allocation layout, such as:
  - non-power-of-two alignment
  - zero/invalid alignment
  - size/alignment combination whose rounded allocation size exceeds `isize::MAX`

## Proof

The vulnerable functions were exported with `#[unsafe(no_mangle)]` and exposed as C ABI functions for libunwind-related use:

```rust
pub unsafe extern "C" fn __rust_c_alloc(size: usize, align: usize) -> *mut u8 {
    unsafe { crate::alloc::alloc(Layout::from_size_align_unchecked(size, align)) }
}

pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize) {
    unsafe { crate::alloc::dealloc(ptr, Layout::from_size_align_unchecked(size, align)) }
}
```

Both functions constructed `Layout` with `Layout::from_size_align_unchecked(size, align)`, which requires the caller to have already upheld the `Layout` invariants.

The checked constructor documents/enforces the relevant invariant:

- alignment must be valid, including being a power of two
- padded allocation size must not exceed `isize::MAX`

The reproducer confirmed that an invalid alignment reaches this unsafe precondition. With UB checks enabled, an equivalent runtime PoC aborts with:

```text
Layout::from_size_align_unchecked requires that align is a power of 2 and the rounded-up allocation size does not exceed isize::MAX
```

Without those optional checks, the invalid `Layout` can propagate into allocator operations, violating Rust library/type invariants.

## Why This Is A Real Bug

The functions are C ABI exports, so their inputs are not constrained by Rust’s safe `Layout` construction APIs.

`Layout::from_size_align_unchecked` is only valid when the caller has already guaranteed the layout invariants. That guarantee is absent at the C boundary. Therefore, malformed native or libunwind-adjacent callers can cause invalid `Layout` construction.

This is not reachable from safe Rust directly, but it is reachable through the exported native interface.

## Fix Requirement

- Replace `Layout::from_size_align_unchecked` with `Layout::from_size_align`.
- On allocation with an invalid layout, return null.
- On deallocation with an invalid layout, ignore the request rather than constructing an invalid `Layout`.

## Patch Rationale

The patch validates external C ABI inputs before constructing a `Layout`:

```rust
pub unsafe extern "C" fn __rust_c_alloc(size: usize, align: usize) -> *mut u8 {
    match Layout::from_size_align(size, align) {
        Ok(layout) => unsafe { crate::alloc::alloc(layout) },
        Err(_) => ptr::null_mut(),
    }
}
```

Invalid allocation requests now fail safely with `null_mut()`, matching conventional C allocation failure behavior.

```rust
pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize) {
    if let Ok(layout) = Layout::from_size_align(size, align) {
        unsafe { crate::alloc::dealloc(ptr, layout) }
    }
}
```

Invalid deallocation requests are ignored, preventing undefined behavior from invalid `Layout` construction. Valid layouts preserve the existing allocator behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/alloc/sgx.rs b/library/std/src/sys/alloc/sgx.rs
index afdef7a5cb6..f2f1ad2611e 100644
--- a/library/std/src/sys/alloc/sgx.rs
+++ b/library/std/src/sys/alloc/sgx.rs
@@ -89,11 +89,16 @@ unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut
 #[cfg(not(test))]
 #[unsafe(no_mangle)]
 pub unsafe extern "C" fn __rust_c_alloc(size: usize, align: usize) -> *mut u8 {
-    unsafe { crate::alloc::alloc(Layout::from_size_align_unchecked(size, align)) }
+    match Layout::from_size_align(size, align) {
+        Ok(layout) => unsafe { crate::alloc::alloc(layout) },
+        Err(_) => ptr::null_mut(),
+    }
 }
 
 #[cfg(not(test))]
 #[unsafe(no_mangle)]
 pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize) {
-    unsafe { crate::alloc::dealloc(ptr, Layout::from_size_align_unchecked(size, align)) }
+    if let Ok(layout) = Layout::from_size_align(size, align) {
+        unsafe { crate::alloc::dealloc(ptr, layout) }
+    }
 }
```