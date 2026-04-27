# Clamp get underflows on empty slice

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`library/core/src/index.rs:57`

## Summary

`Clamp<usize>::get` subtracts `1` from `slice.len()` before validating that the slice is non-empty. For an empty slice, `slice.len() - 1` underflows in a safe public `SliceIndex` path. With overflow checks enabled, this safe `get` panics instead of returning `None`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A safe caller invokes `Clamp<usize>::get` on an empty slice.

## Proof

The vulnerable implementation is:

```rust
fn get(self, slice: &[T]) -> Option<&Self::Output> {
    slice.get(cmp::min(self.0, slice.len() - 1))
}
```

When `slice.len() == 0`, the expression `slice.len() - 1` is evaluated before `cmp::min` can clamp the index. This underflows.

Equivalent reproducer:

```rust
fn clamp_get<T>(idx: usize, slice: &[T]) -> Option<&T> {
    slice.get(std::cmp::min(idx, slice.len() - 1))
}

fn main() {
    let s: &[u8] = &[];
    let _ = clamp_get(0, s);
}
```

Compiled with `-C overflow-checks=yes`, this panics with `attempt to subtract with overflow`.

## Why This Is A Real Bug

`get` is a safe method and should return `None` for an out-of-bounds or unavailable element, not panic due to arithmetic overflow. The method is reachable through the public `SliceIndex` implementation for `Clamp<usize>`. The observable failure depends on build configuration: checked arithmetic panics, while unchecked arithmetic wraps and then returns `None`.

## Fix Requirement

Return `None` when `slice.is_empty()` before evaluating `slice.len() - 1`.

## Patch Rationale

The patch adds an explicit empty-slice guard at the start of `Clamp<usize>::get`. This preserves existing behavior for non-empty slices while preventing the underflow path. For empty slices, `None` is the correct `get` result because no element can be returned.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/index.rs b/library/core/src/index.rs
index 70372163c6e..2464353e366 100644
--- a/library/core/src/index.rs
+++ b/library/core/src/index.rs
@@ -54,6 +54,9 @@ unsafe impl<T> SliceIndex<[T]> for Clamp<usize> {
     type Output = T;
 
     fn get(self, slice: &[T]) -> Option<&Self::Output> {
+        if slice.is_empty() {
+            return None;
+        }
         slice.get(cmp::min(self.0, slice.len() - 1))
     }
```