# overflow constructing Equal iterator

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`library/stdarch/crates/intrinsic-test/src/common/constraint.rs:19`

## Summary

`Constraint::Equal(i64::MAX)` constructs its iterator as `*i..*i + 1`. The endpoint calculation overflows for `i64::MAX` before iteration begins. In debug builds this panics; in optimized builds the endpoint wraps, producing an empty range and violating the invariant that `Equal` yields exactly one value.

## Provenance

Verified from the supplied reproducer and patch details. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- Input can deserialize or otherwise construct `Constraint::Equal(i64::MAX)`.
- A caller invokes `Constraint::iter()` on that value.
- The generated iterator is used by intrinsic-test generation paths.

## Proof

- `Constraint::Equal(i64)` is deserialized as a valid constraint variant.
- JSON parsing can produce `Constraint::Equal(min)` when `min == max`, including `i64::MAX`.
- `Constraint::iter()` matches `Constraint::Equal(i)` and constructs `*i..*i + 1`.
- For `i == i64::MAX`, `*i + 1` overflows during iterator construction.
- The reproducer confirmed:
  - debug build: panic with `attempt to add with overflow`;
  - optimized build: wrapped endpoint makes `Constraint::Equal(i64::MAX).iter().next()` return `None`.

## Why This Is A Real Bug

`Constraint::Equal` semantically represents exactly one permitted value. The current implementation fails for the largest valid `i64`:

- It can crash generator execution in overflow-checking builds.
- It can silently omit the only constrained value in optimized builds.
- The failure occurs before consumer code can handle the value because the overflow happens while constructing the iterator.
- The input value is within the declared type domain of `Equal(i64)`.

## Fix Requirement

`Constraint::Equal` must yield the stored value directly without computing an exclusive upper bound. The iterator implementation must not perform `i + 1` for the equal case.

## Patch Rationale

The patch replaces the one-element range with a one-element slice iterator:

```rust
std::slice::from_ref(i).iter().copied().chain(std::ops::Range::default())
```

This preserves the existing return-shape strategy used by the match arms while avoiding arithmetic entirely. `i64::MAX` is yielded as a normal item, so both debug and optimized builds preserve the `Equal` invariant.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/intrinsic-test/src/common/constraint.rs b/library/stdarch/crates/intrinsic-test/src/common/constraint.rs
index 5984e0fcc22..d6920b6531e 100644
--- a/library/stdarch/crates/intrinsic-test/src/common/constraint.rs
+++ b/library/stdarch/crates/intrinsic-test/src/common/constraint.rs
@@ -16,7 +16,7 @@ impl Constraint {
     /// Iterate over the values of this constraint.
     pub fn iter<'a>(&'a self) -> impl Iterator<Item = i64> + 'a {
         match self {
-            Constraint::Equal(i) => std::slice::Iter::default().copied().chain(*i..*i + 1),
+            Constraint::Equal(i) => std::slice::from_ref(i).iter().copied().chain(std::ops::Range::default()),
             Constraint::Range(range) => std::slice::Iter::default().copied().chain(range.clone()),
             Constraint::Set(items) => items.iter().copied().chain(std::ops::Range::default()),
         }
```