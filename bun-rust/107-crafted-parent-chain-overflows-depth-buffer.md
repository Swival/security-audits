# Crafted Parent Chain Overflows Depth Buffer

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/install/lockfile/Tree.rs:324`

## Summary

A crafted binary lockfile can encode an overlong parent chain in lockfile tree entries. During install, tree iteration calls `relative_path_and_depth`, which follows the parent chain and writes each parent into a fixed-size `DepthBuf = [Id; MAX_DEPTH]`. The pre-patch loop writes to `depth_buf[depth_buf_len]` without first checking `depth_buf_len < MAX_DEPTH`, so an overlong valid parent chain triggers a Rust bounds-check panic and aborts installation.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Crafted lockfile tree entries are loaded and iterated during install.

## Proof

`Iterator::next` iterates nonempty tree entries and calls `relative_path_and_depth`.

For `tree.id > 0`, `relative_path_and_depth` initializes `depth_buf_len = 1` and follows `parent_id` while it is positive and within `trees.len()`. Before the patch, each loop iteration wrote:

```rust
depth_buf[depth_buf_len] = parent_id;
```

with no bound check against `MAX_DEPTH` and no cycle detection.

A crafted binary lockfile with an acyclic chain such as:

```text
tree[MAX_DEPTH].parent = MAX_DEPTH - 1
...
tree[1].parent = 0
tree[MAX_DEPTH].dependencies.len > 0
```

causes iteration of `tree[MAX_DEPTH]` to reach `depth_buf[MAX_DEPTH]`. Rust bounds checking panics at that write, aborting installation.

A cyclic parent chain is also unsafe for this loop because it can keep revisiting parent IDs; however, another parent-walking loop in `src/install/hoisted_install.rs:294` may hang first on cycles. The directly reproduced trigger is the overlong acyclic parent chain.

## Why This Is A Real Bug

The vulnerable data is read from the binary lockfile, not derived solely from trusted in-memory builder output. The loop validates only that `parent_id` is within `trees.len()`, which makes the crafted chain structurally indexable while still exceeding the fixed `DepthBuf` capacity. Rust’s bounds check makes the failure deterministic: the process panics instead of safely rejecting or truncating invalid lockfile structure.

## Fix Requirement

Bound `depth_buf_len` before writing to `depth_buf`, and reject cyclic parent chains so crafted lockfiles cannot force out-of-bounds indexing or unbounded parent traversal.

## Patch Rationale

The patch adds a guard before the fixed-buffer write:

```rust
if depth_buf_len == MAX_DEPTH || depth_buf[1..depth_buf_len].contains(&parent_id) {
    path_buf[path_written] = 0;
    return (ZStr::from_buf(path_buf, path_written), 0);
}
```

This prevents writing `depth_buf[MAX_DEPTH]` and detects repeated parent IDs already seen in the current chain. On invalid structure, it returns the current nul-terminated path with depth `0`, avoiding panic while preserving a safe iterator result.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/Tree.rs b/src/install/lockfile/Tree.rs
index 27a0c0922b..beeb4ada15 100644
--- a/src/install/lockfile/Tree.rs
+++ b/src/install/lockfile/Tree.rs
@@ -323,6 +323,11 @@ pub fn relative_path_and_depth<'b, const PATH_STYLE: IteratorPathStyle>(
         let mut depth_buf_len: usize = 1;
 
         while parent_id > 0 && (parent_id as usize) < trees.len() {
+            if depth_buf_len == MAX_DEPTH || depth_buf[1..depth_buf_len].contains(&parent_id) {
+                path_buf[path_written] = 0;
+                return (ZStr::from_buf(path_buf, path_written), 0);
+            }
+
             depth_buf[depth_buf_len] = parent_id;
             parent_id = trees[parent_id as usize].parent;
             depth_buf_len += 1;
```