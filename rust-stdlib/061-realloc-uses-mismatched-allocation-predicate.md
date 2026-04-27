# realloc uses mismatched allocation predicate

## Classification

Resource lifecycle bug, medium severity.

Confidence: certain.

## Affected Locations

`library/std/src/sys/alloc/unix.rs:52`

## Summary

`System::realloc` selected the raw `libc::realloc` path using `new_size` instead of the original allocation layout size. This could pass a pointer originally allocated by the aligned allocation path to `libc::realloc`, mismatching allocator ownership requirements.

## Provenance

Found by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- The original `Layout` used for allocation requires `aligned_malloc`.
- The same original `Layout` is later supplied to `System::realloc`.
- `new_size` satisfies the malloc-path predicate.
- `new_size` is non-zero, consistent with the unsafe allocation API contract.

Concrete example:

- Original layout: `Layout::from_size_align(1, 16)`
- Original allocation path: aligned allocation, because `align > size`
- Reallocation size: `16`
- Old `realloc` branch result: raw `libc::realloc`

## Proof

`System::alloc` classifies allocations with:

```rust
layout.align() <= MIN_ALIGN && layout.align() <= layout.size()
```

Layouts that fail this predicate use `aligned_malloc`.

Before the patch, `System::realloc` used:

```rust
layout.align() <= MIN_ALIGN && layout.align() <= new_size
```

This differs from the allocation-origin predicate. For an original layout where `align > size`, but a later `new_size >= align`, `realloc` incorrectly dispatches to:

```rust
libc::realloc(ptr as *mut libc::c_void, new_size)
```

That pointer may have originated from `aligned_malloc`, not `malloc`, so the fast path can violate allocator-family ownership requirements.

The reproducer confirmed reachability through public unsafe allocation APIs with a valid custom `Layout`, including `System.alloc(Layout::from_size_align(1, 16))` followed by `System.realloc(..., 16)`. The local macOS allocator did not crash, but the source-level dispatch still demonstrably routes an aligned-allocation-origin pointer into the raw `libc::realloc` branch.

## Why This Is A Real Bug

Allocator APIs require that `realloc` receive a pointer allocated by a compatible allocation function. The original allocation path is determined by the original `Layout`, not by the requested new size.

Using `new_size` to classify the pointer can change allocator families during reallocation. That is a resource lifecycle violation even if some libc implementations tolerate the sequence at runtime.

Safe Rust collection layouts commonly have `size >= align`, making the issue less likely through standard collections, but custom valid `Layout`s can satisfy the documented unsafe API preconditions and trigger the incorrect branch.

## Fix Requirement

Choose the raw `libc::realloc` path only when the original allocation would also have used the raw malloc path.

The predicate in `realloc` must match the allocation-origin predicate from `alloc`:

```rust
layout.align() <= MIN_ALIGN && layout.align() <= layout.size()
```

## Patch Rationale

The patch changes `System::realloc` to classify the pointer using the original `Layout` size instead of `new_size`.

This preserves allocator-family consistency:

- pointers originally allocated by `malloc` may use `libc::realloc`
- pointers originally allocated by `aligned_malloc` use `realloc_fallback`
- `realloc` now matches `alloc` for allocation-origin decisions

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/alloc/unix.rs b/library/std/src/sys/alloc/unix.rs
index 3d369b08abc..9f03b5e7ee8 100644
--- a/library/std/src/sys/alloc/unix.rs
+++ b/library/std/src/sys/alloc/unix.rs
@@ -50,7 +50,7 @@ unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
 
     #[inline]
     unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
-        if layout.align() <= MIN_ALIGN && layout.align() <= new_size {
+        if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() {
             unsafe { libc::realloc(ptr as *mut libc::c_void, new_size) as *mut u8 }
         } else {
             unsafe { realloc_fallback(self, ptr, layout, new_size) }
```