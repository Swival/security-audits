# Out-of-bounds write for zero-sized chunks

## Classification

High severity vulnerability: undefined behavior reachable through safe unstable iterator API.

## Affected Locations

`library/core/src/iter/adapters/filter.rs:43`

## Summary

`Filter::next_chunk::<0>` can dispatch to `next_chunk_dropless` for item types that do not need drop. The dropless implementation allocates a zero-length `MaybeUninit` array, then still enters the source iterator loop and writes to index `0` before checking whether the chunk is full. For `N == 0`, that write is out of bounds and violates `get_unchecked_mut` safety requirements.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes `Filter::next_chunk::<0>`.
- `I::Item` does not need drop, so `Iterator::next_chunk` selects `next_chunk_dropless`.
- The underlying iterator yields at least one element.

## Proof

For `N == 0`, `next_chunk_dropless` creates:

```rust
let mut array: [MaybeUninit<I::Item>; N] = [const { MaybeUninit::uninit() }; N];
let mut initialized = 0;
```

If the source iterator yields an element, `try_for_each` enters the closure with `initialized == 0`:

```rust
let idx = initialized;
initialized = idx + (self.predicate)(&element) as usize;
unsafe { array.get_unchecked_mut(idx) }.write(element);
```

Because `idx == 0` and `array` has length `0`, `array.get_unchecked_mut(0)` is out of bounds. The bounds-dependent break condition runs only after the write:

```rust
if initialized < N { ControlFlow::Continue(()) } else { ControlFlow::Break(()) }
```

The reproduced runtime behavior also showed incorrect consumption: `[10u8, 20].into_iter().filter(...).next_chunk::<0>()` returned `Ok([])` and left `20` as the next element, demonstrating that one source element was consumed on the zero-sized path.

## Why This Is A Real Bug

The implementation performs an unchecked mutable access to index `0` of a zero-length array. This violates the safety precondition of `get_unchecked_mut` and causes undefined behavior. The path is reachable from the safe unstable `Iterator::next_chunk` API when the optimized dropless implementation is selected.

## Fix Requirement

Return `Ok([])` immediately when `N == 0`, before iterating or writing into the temporary array.

## Patch Rationale

The patch adds an early return immediately after constructing the zero-length `MaybeUninit` array:

```rust
if N == 0 {
    // SAFETY: An empty array has no elements that need initialization.
    return Ok(unsafe { MaybeUninit::array_assume_init(array) });
}
```

This prevents `try_for_each` from executing for zero-sized chunks, avoids the out-of-bounds unchecked access, and preserves the expected behavior that requesting a zero-sized chunk does not consume any source element.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/iter/adapters/filter.rs b/library/core/src/iter/adapters/filter.rs
index cf21536784a..ff504d5eb86 100644
--- a/library/core/src/iter/adapters/filter.rs
+++ b/library/core/src/iter/adapters/filter.rs
@@ -39,6 +39,10 @@ fn next_chunk_dropless<const N: usize>(
         &mut self,
     ) -> Result<[I::Item; N], array::IntoIter<I::Item, N>> {
         let mut array: [MaybeUninit<I::Item>; N] = [const { MaybeUninit::uninit() }; N];
+        if N == 0 {
+            // SAFETY: An empty array has no elements that need initialization.
+            return Ok(unsafe { MaybeUninit::array_assume_init(array) });
+        }
         let mut initialized = 0;
 
         let result = self.iter.try_for_each(|element| {
```