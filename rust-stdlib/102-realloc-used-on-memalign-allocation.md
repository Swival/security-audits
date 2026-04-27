# realloc used on memalign allocation

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/std/src/sys/alloc/solid.rs:24`

## Summary

`System::realloc` can call `libc::realloc` on a pointer that `System::alloc` originally obtained from `libc::memalign`. The mismatch occurs because allocation origin depends on both alignment and original size, while reallocation previously checked only alignment and new size.

## Provenance

Detected by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A reachable mismatch exists when:

- The original allocation has `layout.align() <= MIN_ALIGN`.
- The original allocation has `layout.align() > layout.size()`.
- The later reallocation has `new_size >= layout.align()`.

Under these conditions, `alloc` uses `libc::memalign`, but `realloc` uses `libc::realloc`.

## Proof

In `library/std/src/sys/alloc/solid.rs`, `System::alloc` chooses `libc::malloc` only when both conditions hold:

```rust
layout.align() <= MIN_ALIGN && layout.align() <= layout.size()
```

Otherwise, it uses `libc::memalign`.

Before the patch, `System::realloc` chose `libc::realloc` when:

```rust
layout.align() <= MIN_ALIGN && layout.align() <= new_size
```

This omitted the original-size condition used by `alloc`.

Therefore, an allocation with `layout.align() <= MIN_ALIGN` but `layout.align() > layout.size()` is created by `libc::memalign`. If it is later reallocated with `new_size >= layout.align()`, the same pointer is passed directly to `libc::realloc`.

This path is reachable through the default allocator entrypoint: `__rdl_realloc` calls `System::realloc` at `library/std/src/alloc.rs:467`.

## Why This Is A Real Bug

The allocator must preserve pairing invariants between allocation and reallocation routines. A pointer obtained from `libc::memalign` must not be assumed safe for direct `libc::realloc` unless the platform allocator explicitly supports that pairing. The local implementation already distinguishes `malloc`-eligible allocations from `memalign` allocations in `alloc`, but `realloc` failed to make the same distinction.

The reproduced case satisfies the caller-side `GlobalAlloc::realloc` contract and reaches the mismatch entirely through the standard allocator implementation.

## Fix Requirement

`System::realloc` must call `libc::realloc` only for pointers that `System::alloc` would have allocated through the `libc::malloc` branch for the same original layout. For all layouts that may have used `libc::memalign`, it must use `realloc_fallback`.

## Patch Rationale

The patch adds the missing original allocation predicate to the direct `realloc` branch:

```rust
layout.align() <= layout.size()
```

After the change, `System::realloc` calls `libc::realloc` only when all of the following are true:

- `layout.align() <= MIN_ALIGN`
- `layout.align() <= layout.size()`
- `layout.align() <= new_size`

These conditions match the `malloc`-origin condition from `System::alloc` and preserve the existing requirement that the new allocation size can satisfy the requested alignment.

Layouts that would have gone through `memalign` now use `realloc_fallback`, avoiding the allocator-origin mismatch.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/alloc/solid.rs b/library/std/src/sys/alloc/solid.rs
index 47cfa2eb116..3c803798706 100644
--- a/library/std/src/sys/alloc/solid.rs
+++ b/library/std/src/sys/alloc/solid.rs
@@ -20,7 +20,7 @@ unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
     #[inline]
     unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
         unsafe {
-            if layout.align() <= MIN_ALIGN && layout.align() <= new_size {
+            if layout.align() <= MIN_ALIGN && layout.align() <= layout.size() && layout.align() <= new_size {
                 libc::realloc(ptr as *mut libc::c_void, new_size) as *mut u8
             } else {
                 realloc_fallback(self, ptr, layout, new_size)
```