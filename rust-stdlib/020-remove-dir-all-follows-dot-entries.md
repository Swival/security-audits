# remove_dir_all follows dot entries

## Classification

High-severity logic error.

## Affected Locations

`library/std/src/sys/fs/solid.rs:563`

## Summary

`remove_dir_all` on the SOLID backend recursively processes every entry returned by `SOLID_FS_ReadDir` without filtering `.` or `..`. If the platform returns those entries, `.` causes recursion back into the target directory and `..` causes recursion into the parent, allowing deletion to escape the requested directory tree.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`SOLID_FS_ReadDir` returns `.` or `..` entries for a directory.

## Proof

`ReadDir::next` obtains raw directory entries from `SOLID_FS_ReadDir` and yields any entry whose first `d_name` byte is nonzero.

`DirEntry::path` joins the raw `d_name` to the read directory root. Therefore:

- `.` becomes `root\.`
- `..` becomes `root\..`

`remove_dir_all` then iterates all children and calls `child.file_type()`. If the entry is a directory, it recursively calls `remove_dir_all(&child.path())`.

Trigger path:

- Call `std::fs::remove_dir_all` on a SOLID directory.
- `SOLID_FS_ReadDir` returns `..` with `d_type == DT_DIR`, or `DT_UNKNOWN` with `SOLID_FS_Stat(root\..)` reporting a directory.
- The implementation constructs `root\..`.
- `remove_dir_all` recurses into the parent directory.
- Deletion can proceed outside the requested tree, subject to permissions and unlink behavior.

A returned `.` entry constructs `root\.` and recurses into the same directory, causing unbounded recursion/path growth or stack exhaustion instead of being skipped.

## Why This Is A Real Bug

The implementation violates the expected `read_dir` behavior documented in `library/std/src/fs.rs:3191`, where current and parent directory entries are supposed to be skipped.

The affected code performs recursive deletion based on unfiltered directory names from the platform API. Because `..` names the parent directory, this is not limited to denial of service: it can cause recursive deletion outside the caller-specified directory tree.

## Fix Requirement

Skip entries named `.` and `..` before any file-type checks, recursion, or unlink logic in `remove_dir_all`.

## Patch Rationale

The patch filters `child.file_name().as_bytes()` immediately after resolving the `DirEntry` and before calling `child.file_type()` or `child.path()`.

This prevents:

- `.` from recursing into the same directory.
- `..` from recursing into the parent directory.
- either entry from reaching unlink/removal logic.

The change is narrowly scoped to recursive deletion and preserves existing handling for all other entries.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/fs/solid.rs b/library/std/src/sys/fs/solid.rs
index f15a152146e..b8bacf58f44 100644
--- a/library/std/src/sys/fs/solid.rs
+++ b/library/std/src/sys/fs/solid.rs
@@ -560,6 +560,9 @@ pub fn remove_dir_all(path: &Path) -> io::Result<()> {
     for child in readdir(path)? {
         let result: io::Result<()> = try {
             let child = child?;
+            if matches!(child.file_name().as_bytes(), b"." | b"..") {
+                continue;
+            }
             let child_type = child.file_type()?;
             if child_type.is_dir() {
                 remove_dir_all(&child.path())?;
```