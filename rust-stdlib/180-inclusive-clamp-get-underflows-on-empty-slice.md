# Inclusive Clamp Get Underflows On Empty Slice

## Classification

Low severity error-handling bug.

## Affected Locations

`library/core/src/index.rs:174`

## Summary

`Clamp<range::RangeInclusive<usize>>::get` subtracts `1` from `slice.len()` before checking whether the slice is empty. For an empty slice, `slice.len()` is `0`, so `slice.len() - 1` underflows in checked or overflow-checking builds. This makes a safe `get`-style API panic before it can return `None`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A safe caller uses inclusive `Clamp` indexing on an empty slice through the public unstable `SliceIndex::get` implementation for `Clamp<range::RangeInclusive<usize>>`.

## Proof

The vulnerable implementation is:

```rust
fn get(self, slice: &[T]) -> Option<&Self::Output> {
    let start = cmp::min(self.0.start, slice.len() - 1);
    let end = cmp::min(self.0.last, slice.len() - 1);
    (start..=end).get(slice)
}
```

A safe checked-build trigger is:

```rust
#![feature(sliceindex_wrappers)]
#![feature(slice_index_methods)]

use core::index::Clamp;
use core::slice::SliceIndex;

let _ = Clamp(core::range::RangeInclusive { start: 0, last: 0 }).get(&[] as &[u8]);
```

Execution reaches `slice.len() - 1` with `slice.len() == 0`, causing `0usize - 1` to underflow before `(start..=end).get(slice)` can return `None`.

## Why This Is A Real Bug

`SliceIndex::get` is expected to be the non-panicking indexing path that returns `None` for invalid or out-of-bounds accesses. Here, the panic occurs inside safe code while computing the clamped bounds, before delegation to the normal slice indexing implementation. The behavior is therefore an observable error-handling bug in a safe public unstable API.

## Fix Requirement

Avoid subtracting from `slice.len()` when the slice is empty. For `get`, the empty-slice case must return `None`.

## Patch Rationale

The patch replaces the unchecked subtraction with `checked_sub(1)?`:

```rust
let last = slice.len().checked_sub(1)?;
```

For an empty slice, `checked_sub(1)` returns `None`, and `?` makes `get` return `None` directly. For non-empty slices, `last` is the same value as the previous `slice.len() - 1`, preserving existing clamping behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/index.rs b/library/core/src/index.rs
index 70372163c6e..44c2841b08a 100644
--- a/library/core/src/index.rs
+++ b/library/core/src/index.rs
@@ -171,8 +171,9 @@ unsafe impl<T> SliceIndex<[T]> for Clamp<range::RangeInclusive<usize>> {
     type Output = [T];
 
     fn get(self, slice: &[T]) -> Option<&Self::Output> {
-        let start = cmp::min(self.0.start, slice.len() - 1);
-        let end = cmp::min(self.0.last, slice.len() - 1);
+        let last = slice.len().checked_sub(1)?;
+        let start = cmp::min(self.0.start, last);
+        let end = cmp::min(self.0.last, last);
         (start..=end).get(slice)
     }
```