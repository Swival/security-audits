# Patch Creation Path Escapes Patch Directory

## Classification

High severity path traversal.

Confidence: certain.

## Affected Locations

`src/patch/lib.rs:149`

## Summary

Applying an attacker-controlled patch can create or truncate files outside the intended patch directory. New-file paths parsed from patch headers are stored without confinement checks, then passed to `openat` with `O_CREAT | O_WRONLY | O_TRUNC`. Absolute paths ignore `patch_dir`, and `../` path components escape it.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim applies an attacker-controlled patch with filesystem permissions.

## Proof

The parser accepts new-file paths from `diff --git` and `+++` headers. `patch_file_second_pass` stores `file.diff_line_to_path.or(file.to_path)` directly in `FileCreation.path` without rejecting absolute paths or parent-directory traversal.

`PatchFile::apply` then converts `file_creation.path` to `filepath_z` and calls `sys::openat(patch_dir, &filepath_z, O_CREAT | O_WRONLY | O_TRUNC, ...)`.

Minimal triggering patch:

```patch
diff --git a/x b/../victim
new file mode 100644
index 0000000..1111111
--- /dev/null
+++ b/../victim
@@ -0,0 +1,1 @@
+pwn
```

A path such as `../victim` walks above `patch_dir`; an absolute path such as `/tmp/victim` ignores `patch_dir` entirely.

## Why This Is A Real Bug

`openat` does not sandbox arbitrary paths to the supplied directory file descriptor. It only resolves ordinary relative, non-traversing paths beneath that directory. Because attacker-controlled patch paths can contain `..` or be absolute, the file creation path reaches outside the patch directory and can create or truncate files with the victim process permissions.

## Fix Requirement

Reject unsafe patch creation paths before directory creation and before `openat`.

Required rejection criteria:

- Empty path
- Absolute path
- Any normalized path component equal to `..`
- Both `/` and `\` separators, to avoid cross-platform traversal ambiguity

## Patch Rationale

The patch adds an `is_safe_patch_path` guard in the `FileCreation` branch before `mkdir_recursive_at_mode` and `openat`. Unsafe paths now return `EINVAL` and are not used for filesystem operations.

The helper rejects:

- Empty paths
- Paths detected as absolute by `paths::is_absolute_loose`
- Any component equal to `..` when splitting on `/` or `\`

This directly blocks both reproduced escape forms: `../victim` and `/tmp/victim`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/patch/lib.rs b/src/patch/lib.rs
index cf2da18873..9f2e8cb976 100644
--- a/src/patch/lib.rs
+++ b/src/patch/lib.rs
@@ -136,6 +136,10 @@ impl<'a> PatchFile<'a> {
                     }
                 }
                 PatchFilePart::FileCreation(file_creation) => {
+                    if !is_safe_patch_path(file_creation.path) {
+                        return Some(sys::Error::from_code(sys::E::EINVAL, sys::Tag::open));
+                    }
+
                     let filepath_z = ZBox::from_vec_with_nul(file_creation.path.to_vec());
                     let filepath = PathString::init(filepath_z.as_bytes());
                     let filedir = paths::dirname_simple(filepath.slice());
@@ -1071,6 +1075,14 @@ fn parse_file_mode(mode: &[u8]) -> Option<FileMode> {
     FileMode::from_u32(parsed_mode)
 }
 
+fn is_safe_patch_path(path: &[u8]) -> bool {
+    !path.is_empty()
+        && !paths::is_absolute_loose(path)
+        && !path
+            .split(|&c| c == b'/' || c == b'\\')
+            .any(|part| part == b"..")
+}
+
 // ──────────────────────────────────────────────────────────────────────────
 // ScalarSplitIter / LookbackIterator
 // ──────────────────────────────────────────────────────────────────────────
```