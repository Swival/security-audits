# Incorrect Scratch Length Contract

## Classification

Invariant violation, medium severity.

## Affected Locations

`library/core/src/slice/sort/stable/quicksort.rs:10`

## Summary

`quicksort` documented a scratch-buffer requirement that could be smaller than `v.len()`, but the function can call `stable_partition`, which aborts unless `scratch.len() >= v.len()`. A caller satisfying the documented contract could therefore trigger a deterministic abort.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller invokes internal `quicksort` directly.
- Caller supplies `scratch` satisfying the documented `quicksort` requirement.
- `scratch.len()` is shorter than `v.len()`.
- Input length exceeds the stable small-sort threshold.
- `limit > 0`, so execution reaches partitioning.
- Comparator is normal and does not avoid the partition path.

## Proof

For `v.len() == 49`, the documented scratch requirement was:

```text
max(49 - 49 / 2, 48) == 48
```

A scratch buffer of length `48` therefore satisfied the documented precondition.

Because length `49` is above the stable small-sort threshold, `quicksort` does not return through the small-sort path. With `limit > 0`, execution reaches:

```rust
stable_partition(v, scratch, pivot_pos, false, is_less)
```

`stable_partition` then checks:

```rust
if intrinsics::unlikely(scratch.len() < len || pivot_pos >= len) {
    core::intrinsics::abort()
}
```

Since `scratch.len() == 48` and `len == 49`, the documented `quicksort` precondition still reaches `abort()`.

## Why This Is A Real Bug

The public contract of `quicksort` and the actual requirement of its callee disagreed. `stable_partition` requires scratch storage for the full slice length because it writes a partitioned copy of every element in `v` into `scratch` before copying elements back.

Thus, for any `quicksort` call that reaches partitioning, the actual required scratch length is at least `v.len()`. The previous documentation allowed smaller scratch buffers and could mislead valid internal callers into a process abort.

## Fix Requirement

Document and enforce that `scratch.len()` must be at least:

```text
max(v.len(), SMALL_SORT_GENERAL_SCRATCH_LEN)
```

or otherwise ensure that calls to `stable_partition` receive a full-length scratch slice.

## Patch Rationale

The patch corrects the `quicksort` contract to match the implementation requirement already enforced by `stable_partition`. This prevents callers from relying on an insufficient scratch-size formula and makes the abort condition consistent with the documented precondition.

## Residual Risk

None

## Patch

```diff
diff --git a/library/core/src/slice/sort/stable/quicksort.rs b/library/core/src/slice/sort/stable/quicksort.rs
index acc8a5e838e..e316087ade5 100644
--- a/library/core/src/slice/sort/stable/quicksort.rs
+++ b/library/core/src/slice/sort/stable/quicksort.rs
@@ -7,7 +7,7 @@
 use crate::{intrinsics, ptr};
 
 /// Sorts `v` recursively using quicksort.
-/// `scratch.len()` must be at least `max(v.len() - v.len() / 2, SMALL_SORT_GENERAL_SCRATCH_LEN)`
+/// `scratch.len()` must be at least `max(v.len(), SMALL_SORT_GENERAL_SCRATCH_LEN)`
 /// otherwise the implementation may abort.
 ///
 /// `limit` when initialized with `c*log(v.len())` for some c ensures we do not
```