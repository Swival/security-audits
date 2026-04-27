# Undocumented Nonaliasing Precondition

## Classification

Invariant violation, medium severity, certain confidence.

## Affected Locations

`library/core/src/slice/sort/shared/smallsort.rs:643`

## Summary

`sort4_stable` uses `ptr::copy_nonoverlapping` to copy selected elements from `v_base[0..4]` into `dst[0..4]`, but its safety contract originally required only that `v_base` be valid for reads and `dst` be valid for writes. That contract allowed `dst` to overlap the input region, including `dst == v_base`, which can make `copy_nonoverlapping` operate on identical source and destination pointers and trigger undefined behavior.

## Provenance

Reported and verified by Swival Security Scanner: https://swival.dev

## Preconditions

- An unsafe caller invokes `sort4_stable` directly.
- `v_base` is valid for 4 reads.
- `dst` is valid for 4 writes.
- `dst[0..4]` overlaps `v_base[0..4]`, for example `dst == v_base`.

## Proof

`sort4_stable` is declared as a public unsafe function in `library/core/src/slice/sort/shared/smallsort.rs`.

The original safety comment required only:

- `v_base` is valid for 4 reads.
- `dst` is valid for 4 writes.
- The result is stored in `dst[0..4]`.

Those documented preconditions permit a call equivalent to:

```rust
sort4_stable(v.as_ptr(), v.as_mut_ptr(), is_less)
```

For an already sorted input such as `[1u32, 2, 3, 4]`, the selected `min` pointer resolves to `v_base`. The first output write then executes:

```rust
ptr::copy_nonoverlapping(min, dst, 1);
```

with `min == dst == v_base`.

For one non-ZST element, identical source and destination pointers overlap. `ptr::copy_nonoverlapping` requires the source and destination ranges not to overlap, so this call violates its contract and causes undefined behavior under the stated `sort4_stable` safety contract.

## Why This Is A Real Bug

This is not only an internal caller issue. `sort4_stable` is `pub unsafe fn`, so its documented safety requirements define what direct unsafe callers must uphold. The implementation relies on a stricter invariant than the documentation stated: the input and output regions must be disjoint.

Current committed internal callers appear to pass scratch buffers that do not alias `v_base`, but the function’s own unsafe contract was insufficient. A caller satisfying the documented requirements could still trigger undefined behavior.

## Fix Requirement

The unsafe contract must require that `v_base[0..4]` and `dst[0..4]` do not overlap, or the implementation must use alias-safe operations that tolerate overlapping source and destination regions.

## Patch Rationale

The patch documents the missing nonaliasing invariant directly in the `sort4_stable` safety comment:

```diff
 /// SAFETY: The caller MUST guarantee that `v_base` is valid for 4 reads and
-/// `dst` is valid for 4 writes. The result will be stored in `dst[0..4]`.
+/// `dst` is valid for 4 writes. The regions `v_base[0..4]` and `dst[0..4]`
+/// MUST NOT overlap. The result will be stored in `dst[0..4]`.
```

This aligns the public unsafe preconditions with the implementation’s use of `ptr::copy_nonoverlapping`.

## Residual Risk

None

## Patch

`130-undocumented-nonaliasing-precondition.patch`

```diff
diff --git a/library/core/src/slice/sort/shared/smallsort.rs b/library/core/src/slice/sort/shared/smallsort.rs
index e555fce4408..ee951ecb1c3 100644
--- a/library/core/src/slice/sort/shared/smallsort.rs
+++ b/library/core/src/slice/sort/shared/smallsort.rs
@@ -608,7 +608,8 @@ pub fn insertion_sort_shift_left<T, F: FnMut(&T, &T) -> bool>(
 }
 
 /// SAFETY: The caller MUST guarantee that `v_base` is valid for 4 reads and
-/// `dst` is valid for 4 writes. The result will be stored in `dst[0..4]`.
+/// `dst` is valid for 4 writes. The regions `v_base[0..4]` and `dst[0..4]`
+/// MUST NOT overlap. The result will be stored in `dst[0..4]`.
 pub unsafe fn sort4_stable<T, F: FnMut(&T, &T) -> bool>(
     v_base: *const T,
     dst: *mut T,
```