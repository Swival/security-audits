# any comparisons return non-boolean values

## Classification

Logic error, medium severity, certain confidence.

## Affected Locations

`library/stdarch/crates/core_arch/src/s390x/vector.rs:5888`

`library/stdarch/crates/core_arch/src/s390x/vector.rs:5896`

`library/stdarch/crates/core_arch/src/s390x/vector.rs:5904`

`library/stdarch/crates/core_arch/src/s390x/vector.rs:5912`

## Summary

The public s390x vector “any” ordered-comparison wrappers returned bitwise complements of `0`/`1` integer results instead of normalized C-style booleans. This made logical false evaluate to `-2`, which is nonzero, so callers using `result != 0` treated false comparisons as true.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

A caller uses one of these public APIs and interprets the `i32` result as a C-style boolean:

- `vec_any_lt`
- `vec_any_le`
- `vec_any_gt`
- `vec_any_ge`

The target is s390x with the `vector` target feature enabled.

## Proof

`vec_all_lt`, `vec_all_le`, `vec_all_gt`, and `vec_all_ge` are implemented with `simd_reduce_all(... ) as i32`, so they return normalized integer booleans: `0` or `1`.

Before the patch, the “any” wrappers inverted those values with bitwise integer NOT:

```rust
pub unsafe fn vec_any_lt<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
    !vec_all_ge(a, b)
}
```

For `i32`, bitwise NOT does not perform logical negation:

```rust
!0i32 == -1
!1i32 == -2
```

Therefore:

- logical true returned `-1`
- logical false returned `-2`
- both values are nonzero

Concrete trigger on s390x with `vector`:

```rust
vec_any_lt(
    vector_signed_int([1, 1, 1, 1]),
    vector_signed_int([1, 1, 1, 1]),
)
```

No lane is less-than, so `vec_all_ge(a, b)` is `1`. The old implementation returned `!1`, which is `-2`, causing `result != 0` to evaluate as true.

## Why This Is A Real Bug

The affected APIs return `i32` predicates and are named as boolean-style “any” comparisons. Other predicate helpers in the same file normalize results with `simd_reduce_any(... ) as i32` or `i32::from(condition)`, producing `0` or `1`.

Returning `-2` for false violates that convention and breaks common C-style boolean checks. Downstream control flow that checks `if result != 0` can always take the true branch for these ordered “any” comparisons.

## Fix Requirement

Replace bitwise negation of the complementary “all” predicate with boolean normalization:

```rust
i32::from(complementary_all_result == 0)
```

This must be applied to all four ordered “any” comparison wrappers.

## Patch Rationale

The patch preserves the existing complement-based logic while changing only the integer negation operation. `i32::from(vec_all_*(...) == 0)` computes logical negation and normalizes the public result to `0` or `1`.

This matches the expected C-style boolean contract and avoids changing type bounds, target features, or comparison semantics.

## Residual Risk

None

## Patch

```diff
diff --git a/library/stdarch/crates/core_arch/src/s390x/vector.rs b/library/stdarch/crates/core_arch/src/s390x/vector.rs
index fc5af1b14d0..8b24547ebbb 100644
--- a/library/stdarch/crates/core_arch/src/s390x/vector.rs
+++ b/library/stdarch/crates/core_arch/src/s390x/vector.rs
@@ -5888,7 +5888,7 @@ pub unsafe fn vec_all_nge<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
 #[target_feature(enable = "vector")]
 #[unstable(feature = "stdarch_s390x", issue = "135681")]
 pub unsafe fn vec_any_lt<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
-    !vec_all_ge(a, b)
+    i32::from(vec_all_ge(a, b) == 0)
 }
 
 /// Any Elements Less Than or Equal
@@ -5896,7 +5896,7 @@ pub unsafe fn vec_any_lt<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
 #[target_feature(enable = "vector")]
 #[unstable(feature = "stdarch_s390x", issue = "135681")]
 pub unsafe fn vec_any_le<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
-    !vec_all_gt(a, b)
+    i32::from(vec_all_gt(a, b) == 0)
 }
 
 /// Any Elements Greater Than
@@ -5904,7 +5904,7 @@ pub unsafe fn vec_any_le<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
 #[target_feature(enable = "vector")]
 #[unstable(feature = "stdarch_s390x", issue = "135681")]
 pub unsafe fn vec_any_gt<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
-    !vec_all_le(a, b)
+    i32::from(vec_all_le(a, b) == 0)
 }
 
 /// Any Elements Greater Than or Equal
@@ -5912,7 +5912,7 @@ pub unsafe fn vec_any_gt<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
 #[target_feature(enable = "vector")]
 #[unstable(feature = "stdarch_s390x", issue = "135681")]
 pub unsafe fn vec_any_ge<T: sealed::VectorCompare>(a: T, b: T) -> i32 {
-    !vec_all_lt(a, b)
+    i32::from(vec_all_lt(a, b) == 0)
 }
 
 /// Any Elements Not Less Than
```