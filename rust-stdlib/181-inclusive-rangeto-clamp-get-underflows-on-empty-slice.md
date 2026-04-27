# Inclusive RangeTo Clamp `get` Underflows On Empty Slice

## Classification

Validation gap; low severity; confidence certain.

## Affected Locations

`library/core/src/index.rs:354`

`library/core/src/index.rs:385`

## Summary

`Clamp(..=end).get` for inclusive range-to slice indexing subtracts `1` from `slice.len()` before checking whether the slice is empty. For an empty slice, `slice.len() - 1` underflows in safe code. The bug affects both inclusive range-to wrapper variants and is reachable through the public `SliceIndex::get` path.

## Provenance

Reported and validated from Swival Security Scanner: https://swival.dev

## Preconditions

A caller invokes `Clamp(..=end).get` on an empty slice.

Example trigger:

```rust
Clamp(..=0usize).get(&[] as &[u8])
```

## Proof

The affected implementations compute the inclusive end as:

```rust
cmp::min(self.0.end, slice.len() - 1)
```

or, for the internal range wrapper:

```rust
cmp::min(self.0.last, slice.len() - 1)
```

When `slice.len()` is `0`, the subtraction `0usize - 1` underflows before `cmp::min` can clamp the value. The delegated slice indexing operation is reached only after this failing expression.

The reproducer confirmed that the equivalent safe expression:

```rust
(..=cmp::min(end, slice.len() - 1)).get(empty_slice)
```

panics with `attempt to subtract with overflow` when compiled with overflow checks.

## Why This Is A Real Bug

`SliceIndex::get` is a safe API and should not panic due to arithmetic underflow while attempting to clamp an index. The intended behavior for an empty slice is the clamped empty prefix result. Instead:

- overflow-checking builds panic before normal slice bounds handling
- unchecked arithmetic builds wrap and produce behavior dependent on overflow semantics
- the bug is reachable without unsafe code
- the clamping logic fails specifically on the valid empty-slice boundary case

## Fix Requirement

Avoid subtracting from `slice.len()` when the slice may be empty. Compute the inclusive range-to clamp as an exclusive upper bound capped by `slice.len()`, so an empty slice naturally yields `..0`.

## Patch Rationale

The patch replaces the inclusive range construction with an equivalent exclusive range construction:

```rust
(..cmp::min(end.saturating_add(1), slice.len())).get(slice)
```

This preserves inclusive range-to semantics for non-empty slices by converting `..=end` to `..end + 1`, while avoiding both empty-slice underflow and `usize::MAX + 1` overflow through `saturating_add(1)`. Because the final bound is clamped to `slice.len()`, empty slices produce `..0` and return the expected empty slice.

Both affected implementations are patched:

- `Clamp<range::RangeToInclusive<usize>>::get`
- `Clamp<ops::RangeToInclusive<usize>>::get`

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/index.rs b/library/core/src/index.rs
index 70372163c6e..ff6a816aee6 100644
--- a/library/core/src/index.rs
+++ b/library/core/src/index.rs
@@ -350,7 +350,7 @@ unsafe impl<T> SliceIndex<[T]> for Clamp<range::RangeToInclusive<usize>> {
     type Output = [T];
 
     fn get(self, slice: &[T]) -> Option<&Self::Output> {
-        (..=cmp::min(self.0.last, slice.len() - 1)).get(slice)
+        (..cmp::min(self.0.last.saturating_add(1), slice.len())).get(slice)
     }
 
     fn get_mut(self, slice: &mut [T]) -> Option<&mut Self::Output> {
@@ -381,7 +381,7 @@ unsafe impl<T> SliceIndex<[T]> for Clamp<ops::RangeToInclusive<usize>> {
     type Output = [T];
 
     fn get(self, slice: &[T]) -> Option<&Self::Output> {
-        (..=cmp::min(self.0.end, slice.len() - 1)).get(slice)
+        (..cmp::min(self.0.end.saturating_add(1), slice.len())).get(slice)
     }
 
     fn get_mut(self, slice: &mut [T]) -> Option<&mut Self::Output> {
```