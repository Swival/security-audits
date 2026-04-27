# Unchecked C Deallocation Layout

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/alloc/sgx.rs:91`

## Summary

`__rust_c_dealloc` accepts `size` and `align` from an external C ABI caller and constructs a `Layout` with `Layout::from_size_align_unchecked`. Invalid caller-controlled values can therefore violate `Layout` invariants before calling `crate::alloc::dealloc`, producing undefined behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An external C caller linked into the SGX image calls:

```rust
__rust_c_dealloc(ptr, size, align)
```

with an invalid layout input, such as:

- `align = 0`
- `align = 3`
- a `size` whose rounded-up allocation size exceeds `isize::MAX`

## Proof

`__rust_c_dealloc` is exported with `#[unsafe(no_mangle)]` and uses the C ABI:

```rust
pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize)
```

The function directly constructs a layout from the external parameters:

```rust
Layout::from_size_align_unchecked(size, align)
```

That unchecked layout is then passed to:

```rust
crate::alloc::dealloc(ptr, layout)
```

The reproduced evidence confirms:

- `size` and `align` enter through extern `"C"` parameters.
- `Layout::from_size_align_unchecked` bypasses checks for nonzero power-of-two alignment and rounded size bounds.
- `Layout` requires alignment to be a power of two and rounded size to fit in `isize`.
- With UB checks enabled, invalid inputs can abort via unsafe precondition checks.
- Without UB checks, invalid inputs create an invalid `Layout` and make the deallocation call undefined behavior.

## Why This Is A Real Bug

The unsafe boundary is the exported C function. Although the function itself is `unsafe`, it accepts raw ABI inputs from non-Rust callers and then creates a Rust `Layout` using an unchecked constructor.

`Layout::from_size_align_unchecked` requires the caller to prove that:

- `align` is nonzero.
- `align` is a power of two.
- the rounded-up allocation size does not exceed `isize::MAX`.

`__rust_c_dealloc` did not enforce those requirements before passing the layout to `crate::alloc::dealloc`. Therefore an invalid C/FFI caller can trigger undefined behavior inside Rust allocation code.

No source evidence showed that an honest libunwind path supplies invalid values; the practical trigger is an invalid linked C/FFI caller.

## Fix Requirement

Replace `Layout::from_size_align_unchecked` with checked layout construction.

If `Layout::from_size_align(size, align)` returns `Err`, `__rust_c_dealloc` must not call `crate::alloc::dealloc`.

## Patch Rationale

The patch validates the C-provided `size` and `align` before deallocation:

```rust
if let Ok(layout) = Layout::from_size_align(size, align) {
    unsafe { crate::alloc::dealloc(ptr, layout) }
}
```

This preserves normal behavior for valid layouts while preventing invalid external parameters from constructing an invalid `Layout`.

Invalid deallocation requests are ignored rather than forwarded to the allocator, avoiding the undefined behavior caused by violating `Layout` and `dealloc` preconditions.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/alloc/sgx.rs b/library/std/src/sys/alloc/sgx.rs
index afdef7a5cb6..4d1117de75a 100644
--- a/library/std/src/sys/alloc/sgx.rs
+++ b/library/std/src/sys/alloc/sgx.rs
@@ -95,5 +95,7 @@ unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut
 #[cfg(not(test))]
 #[unsafe(no_mangle)]
 pub unsafe extern "C" fn __rust_c_dealloc(ptr: *mut u8, size: usize, align: usize) {
-    unsafe { crate::alloc::dealloc(ptr, Layout::from_size_align_unchecked(size, align)) }
+    if let Ok(layout) = Layout::from_size_align(size, align) {
+        unsafe { crate::alloc::dealloc(ptr, layout) }
+    }
 }
```