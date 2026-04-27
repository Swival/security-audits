# panic during clone drops uninitialized elements

## Classification

Invariant violation causing undefined behavior during panic unwinding.

Severity: high.

Confidence: certain.

## Affected Locations

`library/core/src/iter/adapters/map_windows.rs:196`

## Summary

`Buffer<T, N>::clone` constructed a destination `Buffer` with uninitialized storage and copied `start` before cloning the source array into it. If `T::clone` panicked while cloning `[T; N]`, unwinding dropped the partially constructed local `Buffer`. Its `Drop` implementation assumes `N` initialized elements at `start` and drops them unconditionally, so it dropped uninitialized memory as `T`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- A `MapWindows` value is cloned.
- Its inner `buffer` is `Some(Buffer<_, N>)`.
- `I::Item: Clone`.
- Cloning one of the window items panics during `[T; N]::clone()`.

## Proof

`MapWindows::clone` clones `inner`, and `MapWindowsInner::clone` clones `self.buffer`.

For `Some(Buffer)`, `Buffer::clone` previously did:

```rust
let mut buffer = Buffer {
    buffer: [[const { MaybeUninit::uninit() }; N], [const { MaybeUninit::uninit() }; N]],
    start: self.start,
};
buffer.as_uninit_array_mut().write(self.as_array_ref().clone());
buffer
```

The destination `buffer` is a live local with `start` copied from the source, but its backing storage contains only `MaybeUninit::uninit()` values. The subsequent `self.as_array_ref().clone()` is evaluated before `write` initializes the destination. If `T::clone` panics there, `buffer` is dropped during unwinding.

`Drop for Buffer` then executes:

```rust
let initialized_part: *mut [T] = crate::ptr::slice_from_raw_parts_mut(
    self.buffer_mut_ptr().add(self.start).cast(),
    N,
);
ptr::drop_in_place(initialized_part);
```

That drop path assumes the invariant that `N` elements starting at `self.start` are initialized. In this failure path, they are not initialized.

The reproducer confirmed the behavior with a standalone equivalent of the `Buffer::clone`/`Drop` logic: a panicking `Clone` caused a garbage `Bomb` value to be dropped and then crashed with `Bus error`.

## Why This Is A Real Bug

The `Buffer` invariant states that `self.buffer[self.start..self.start + N]` is initialized. The old `clone` implementation created a `Buffer` value for which that invariant was false, then performed a panic-capable operation before restoring the invariant.

Rust unwinding drops initialized local variables. Because the destination `Buffer` was already considered initialized as a Rust value, its `Drop` implementation ran even though its logical initialized-elements invariant had not been established. Dropping uninitialized memory as `T` is undefined behavior.

## Fix Requirement

`Buffer::clone` must not make a destination `Buffer` observable to unwinding until its initialized-elements invariant is true.

Acceptable fixes include:

- Clone the source `[T; N]` before constructing the destination `Buffer`.
- Or use a guard that accurately tracks the number of initialized elements and only drops those elements during unwinding.

## Patch Rationale

The patch clones the source initialized array first:

```rust
let cloned = self.as_array_ref().clone();
```

Only after that clone succeeds does it construct the destination `Buffer` and write the fully cloned array into the uninitialized destination storage.

If `T::clone` panics, no destination `Buffer` exists yet, so no `Buffer::drop` can run on uninitialized destination elements. If cloning succeeds, the write initializes the `N` elements before the `Buffer` is returned, preserving the invariant.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/iter/adapters/map_windows.rs b/library/core/src/iter/adapters/map_windows.rs
index 097a0745c61..e4235af474f 100644
--- a/library/core/src/iter/adapters/map_windows.rs
+++ b/library/core/src/iter/adapters/map_windows.rs
@@ -194,11 +194,12 @@ fn push(&mut self, next: T) {
 
 impl<T: Clone, const N: usize> Clone for Buffer<T, N> {
     fn clone(&self) -> Self {
+        let cloned = self.as_array_ref().clone();
         let mut buffer = Buffer {
             buffer: [[const { MaybeUninit::uninit() }; N], [const { MaybeUninit::uninit() }; N]],
             start: self.start,
         };
-        buffer.as_uninit_array_mut().write(self.as_array_ref().clone());
+        buffer.as_uninit_array_mut().write(cloned);
         buffer
     }
 }
```