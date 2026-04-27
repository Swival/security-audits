# Unchecked Alignment Forms Invalid Layout

## Classification

Validation gap; medium severity.

## Affected Locations

`library/std/src/sys/pal/wasi/cabi_realloc.rs:46`

## Summary

`cabi_realloc` accepted `align` across an `extern "C"` ABI boundary and used it to construct `Layout` values with `Layout::from_size_align_unchecked`. Because `align` was not validated as nonzero and power-of-two, an ABI caller could cause construction of an invalid `Layout`, violating `Layout` invariants before allocation.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes `cabi_realloc` through the ABI boundary.
- Caller supplies an `align` value that is not a valid `Layout` alignment.
- For the allocation path, `old_len == 0` and `new_len != 0`.
- For the reallocation path, `old_len != 0`.

## Proof

`align` is an `extern "C"` parameter to `cabi_realloc`, so it is ABI-controlled input.

When `old_len == 0` and `new_len != 0`, the original code called:

```rust
Layout::from_size_align_unchecked(new_len, align)
```

When `old_len != 0`, the original code called:

```rust
Layout::from_size_align_unchecked(old_len, align)
```

`Layout::from_size_align_unchecked` requires `Layout::is_size_align_valid(size, align)`. Valid alignment requires `Alignment::new(align)`, which rejects zero and non-powers-of-two. The unchecked constructor then builds a `Layout` using the supplied alignment, creating a value whose documented invariant requires a power-of-two alignment.

Debug or UB-checking builds can abort on the violated unsafe precondition. Release builds can pass the invalid `Layout` into allocator code, including paths that read `layout.align()` while relying on the already-broken invariant.

## Why This Is A Real Bug

The invalid value is reachable directly from ABI-controlled input. No prior validation proves that `align` satisfies `Layout` requirements before the unsafe constructor is called. This is not merely a failed allocation case: the bug occurs at layout construction time, before allocation, by violating the unsafe precondition of `Layout::from_size_align_unchecked`.

## Fix Requirement

Replace unchecked layout construction with checked construction using `Layout::from_size_align`, and handle invalid layout errors before calling allocator functions.

## Patch Rationale

The patch replaces both unsafe unchecked constructors with checked layout construction:

```rust
Layout::from_size_align(new_len, align).unwrap_or_else(|_| super::abort_internal())
Layout::from_size_align(old_len, align).unwrap_or_else(|_| super::abort_internal())
```

This enforces `Layout` invariants before allocation or reallocation. Invalid ABI-supplied alignment now follows the existing abort behavior instead of creating an invalid `Layout`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/wasi/cabi_realloc.rs b/library/std/src/sys/pal/wasi/cabi_realloc.rs
index 78adf9002fd..8d3a280234b 100644
--- a/library/std/src/sys/pal/wasi/cabi_realloc.rs
+++ b/library/std/src/sys/pal/wasi/cabi_realloc.rs
@@ -44,11 +44,11 @@
         if new_len == 0 {
             return ptr::without_provenance_mut(align);
         }
-        layout = Layout::from_size_align_unchecked(new_len, align);
+        layout = Layout::from_size_align(new_len, align).unwrap_or_else(|_| super::abort_internal());
         alloc::alloc(layout)
     } else {
         debug_assert_ne!(new_len, 0, "non-zero old_len requires non-zero new_len!");
-        layout = Layout::from_size_align_unchecked(old_len, align);
+        layout = Layout::from_size_align(old_len, align).unwrap_or_else(|_| super::abort_internal());
         alloc::realloc(old_ptr, layout, new_len)
     };
     if ptr.is_null() {
```