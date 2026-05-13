# Crafted Dependency Path Overflows Path Buffer

## Classification

denial of service, medium severity

## Affected Locations

- `src/install/lockfile/Tree.rs:345`

## Summary

A crafted binary lockfile can encode dependency names and tree depth that produce a relative dependency path longer than `PathBuffer`. During install iteration, `relative_path_and_depth` writes dependency path components into the fixed-size buffer without validating remaining capacity. Rust slice bounds checks then panic, aborting installation.

## Provenance

- Verified by Swival.dev Security Scanner: https://swival.dev
- Reproduced locally from the reported control flow and affected source.
- Confidence: certain.

## Preconditions

- Victim runs install using an attacker-controlled Bun lockfile.
- The lockfile contains tree/dependency data whose accumulated path exceeds `PathBuffer`.
- The malformed path is reached by lockfile tree iteration.

## Proof

`Iterator::next` calls `relative_path_and_depth` for each tree using shared lockfile buffers.

In `relative_path_and_depth`, parent tree IDs are walked and each folder name is obtained with:

```rust
let name = trees[id as usize].folder_name(dependencies, buf);
```

`Tree::folder_name` returns dependency name bytes from lockfile string data:

```rust
deps[dep_id as usize].name.slice(buf)
```

Before the patch, these bytes were copied into `path_buf` without checking capacity:

```rust
path_buf[path_written..path_written + name.len()].copy_from_slice(name);
```

Separator writes and `node_modules` writes were also unchecked:

```rust
path_buf[path_written] = SEP;
path_buf[path_written + 1..path_written + 1 + b"node_modules".len()]
    .copy_from_slice(b"node_modules");
```

A binary lockfile can therefore choose dependency names and tree depth such that `path_written + name.len()` or subsequent suffix writes exceed `MAX_PATH_BYTES`. This triggers Rust bounds-check panic during install iteration.

## Why This Is A Real Bug

The failure is attacker-controlled because binary lockfile loading validates buffer offsets but does not enforce total tree path length. `verify_data` is debug-only and does not validate generated tree paths. `Tree::folder_name` can return arbitrary-length external dependency names through `SemverString::slice`.

The impact is denial of service: install aborts when path construction panics. The bound is platform-dependent but fixed, e.g. `PathBuffer` is 4096 bytes on Linux and 1024 bytes on macOS.

## Fix Requirement

Reject malformed lockfiles before any write can exceed `PathBuffer` capacity, including:

- parent depth accumulation into `depth_buf`
- path separators
- dependency folder names
- trailing `/node_modules`
- final NUL terminator space

## Patch Rationale

The patch adds a single failure path:

```rust
let path_too_long = || -> ! {
    Output::err_generic("Lockfile is malformed (dependency path is too long)", ());
    bun_core::Global::crash();
};
```

It then guards every capacity-sensitive operation before writing:

- checks one-byte separator writes leave room within `MAX_PATH_BYTES`
- uses `checked_add` for dependency name length arithmetic
- requires copied names to end before `MAX_PATH_BYTES`, preserving space for termination
- checks `/node_modules` suffix length before writing it

(Excessive parent depth and cyclic parent chains are addressed by finding 107, which is a separate patch on the same function.)

This converts an uncontrolled bounds-check panic into explicit malformed-lockfile rejection.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/lockfile/Tree.rs b/src/install/lockfile/Tree.rs
index 27a0c0922b..0a0f67f257 100644
--- a/src/install/lockfile/Tree.rs
+++ b/src/install/lockfile/Tree.rs
@@ -316,6 +316,11 @@ pub fn relative_path_and_depth<'b, const PATH_STYLE: IteratorPathStyle>(
         IteratorPathStyle::PkgPath => 0,
     };
 
+    let path_too_long = || -> ! {
+        Output::err_generic("Lockfile is malformed (dependency path is too long)", ());
+        bun_core::Global::crash();
+    };
+
     depth_buf[0] = 0;
 
     if tree.id > 0 {
@@ -323,6 +328,9 @@ pub fn relative_path_and_depth<'b, const PATH_STYLE: IteratorPathStyle>(
         let mut depth_buf_len: usize = 1;
 
         while parent_id > 0 && (parent_id as usize) < trees.len() {
+            if depth_buf_len >= MAX_DEPTH {
+                path_too_long();
+            }
             depth_buf[depth_buf_len] = parent_id;
             parent_id = trees[parent_id as usize].parent;
             depth_buf_len += 1;
@@ -334,21 +342,34 @@ pub fn relative_path_and_depth<'b, const PATH_STYLE: IteratorPathStyle>(
         while depth_buf_len > 0 {
             if PATH_STYLE == IteratorPathStyle::PkgPath {
                 if depth_buf_len != depth {
+                    if path_written + 1 >= MAX_PATH_BYTES {
+                        path_too_long();
+                    }
                     path_buf[path_written] = b'/';
                     path_written += 1;
                 }
             } else {
+                if path_written + 1 >= MAX_PATH_BYTES {
+                    path_too_long();
+                }
                 path_buf[path_written] = SEP;
                 path_written += 1;
             }
 
             let id = depth_buf[depth_buf_len];
             let name = trees[id as usize].folder_name(dependencies, buf);
-            path_buf[path_written..path_written + name.len()].copy_from_slice(name);
-            path_written += name.len();
+            let name_end = match path_written.checked_add(name.len()) {
+                Some(end) if end < MAX_PATH_BYTES => end,
+                _ => path_too_long(),
+            };
+            path_buf[path_written..name_end].copy_from_slice(name);
+            path_written = name_end;
 
             if PATH_STYLE == IteratorPathStyle::NodeModules {
                 // Zig: std.fs.path.sep_str ++ "node_modules" (always 13 bytes)
+                if path_written + b"/node_modules".len() >= MAX_PATH_BYTES {
+                    path_too_long();
+                }
                 path_buf[path_written] = SEP;
                 path_buf[path_written + 1..path_written + 1 + b"node_modules".len()]
                     .copy_from_slice(b"node_modules");
```