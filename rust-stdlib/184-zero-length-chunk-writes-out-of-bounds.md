# Zero-Length Chunk Writes Out Of Bounds

## Classification

High-severity memory safety vulnerability: out-of-bounds write and undefined behavior reachable from safe Rust code.

## Affected Locations

`library/core/src/iter/adapters/filter_map.rs:103`

## Summary

`FilterMap::next_chunk::<0>` does not special-case zero-length chunks. When the source iterator yields at least one element, the implementation enters `try_for_each`, computes `idx = 0`, and writes one `MaybeUninit<B>` value into `guard.array`, even though `guard.array` has length zero.

The later break condition runs only after the write, so it cannot prevent the out-of-bounds access.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes `FilterMap::next_chunk::<0>`.
- The wrapped source iterator yields at least one item.
- The call is made from otherwise safe Rust code.

## Proof

The affected implementation allocates:

```rust
let mut array: [MaybeUninit<Self::Item>; N] = [const { MaybeUninit::uninit() }; N];
```

For `N == 0`, this is a zero-length array. The function then still enters:

```rust
let result = self.iter.try_for_each(|element| {
```

On the first source element:

```rust
let idx = guard.initialized;
```

`idx` is `0`. The unsafe block then computes a destination inside the zero-length buffer:

```rust
let dst = guard.array.as_mut_ptr().add(idx);
crate::ptr::copy_nonoverlapping(opt_payload_at, dst, 1);
```

For `N == 0`, writing one element to `dst` is out of bounds. The guard condition:

```rust
if guard.initialized < N { ControlFlow::Continue(()) } else { ControlFlow::Break(()) }
```

executes only after the write.

Minimal trigger:

```rust
#![feature(iter_next_chunk)]

fn main() {
    let mut it = core::iter::once(())
        .filter_map(|_| Some([0xAAu8; 4096]));

    let _ = it.next_chunk::<0>();
}
```

The reproduced runtime PoC crashed with `Bus error` using a large non-ZST payload, consistent with stack memory corruption.

## Why This Is A Real Bug

`next_chunk::<0>()` is a valid const-generic instantiation. Safe caller code can invoke it.

The implementation’s safety comment says loop conditions ensure the index is in bounds, but for `N == 0` the loop condition is checked after `copy_nonoverlapping`. Therefore the unsafe block writes outside the destination array before any control-flow break can occur.

This violates Rust’s memory safety guarantees and causes undefined behavior from safe code.

## Fix Requirement

Return `Ok([])` immediately when `N == 0`, before iterating the source iterator and before constructing any write destination into the zero-length array.

## Patch Rationale

The patch adds an early return immediately after allocating the `[MaybeUninit<Self::Item>; N]` array:

```rust
if N == 0 {
    return Ok(unsafe { MaybeUninit::array_assume_init(array) });
}
```

For `N == 0`, the array has no initialized elements to produce or drop. `MaybeUninit::array_assume_init(array)` is sound because there are zero elements requiring initialization.

This preserves existing behavior for `N > 0` while preventing the unsafe write path from executing for zero-length chunks.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/iter/adapters/filter_map.rs b/library/core/src/iter/adapters/filter_map.rs
index 3fd7e16d1c1..27ef60405bd 100644
--- a/library/core/src/iter/adapters/filter_map.rs
+++ b/library/core/src/iter/adapters/filter_map.rs
@@ -70,6 +70,10 @@ fn next_chunk<const N: usize>(
     ) -> Result<[Self::Item; N], array::IntoIter<Self::Item, N>> {
         let mut array: [MaybeUninit<Self::Item>; N] = [const { MaybeUninit::uninit() }; N];
 
+        if N == 0 {
+            return Ok(unsafe { MaybeUninit::array_assume_init(array) });
+        }
+
         struct Guard<'a, T> {
             array: &'a mut [MaybeUninit<T>],
             initialized: usize,
```