# Patch Deletion Path Escapes Patch Directory

## Classification

Path traversal, high severity.

## Affected Locations

`src/patch/lib.rs:100`

## Summary

Attacker-controlled delete-file paths from patch input were passed directly to `unlinkat` relative to the patch directory file descriptor. Absolute paths and paths containing `..` could escape the intended patch directory and delete arbitrary non-directory files with the Bun install process privileges.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim applies an attacker-supplied patch containing a delete-file entry.

## Proof

`patch_file_second_pass` builds `FileDeletion.path` from `diff_line_from_path` or `from_path` without rejecting absolute paths or parent traversal components.

`PatchFile::apply` then handles `PatchFilePart::FileDeletion` by copying `file_deletion.path` into a NUL-terminated buffer and passing it directly to `sys::unlinkat(patch_dir, &pathz)`.

On Unix, `sys::unlinkat` calls `libc::unlinkat(dirfd, path, flags)`. POSIX path resolution allows `..` to traverse above `dirfd`, and absolute paths ignore `dirfd` entirely. A local runtime check confirmed both `unlinkat(dirfd, "../outside_rel.txt", 0)` and `unlinkat(dirfd, "/tmp/.../outside_abs.txt", 0)` deleted files outside the opened directory.

Reachability is through patch installation: `src/install/patch_install.rs:448` parses the patch file and `src/install/patch_install.rs:571` applies it to the temporary package directory fd.

## Why This Is A Real Bug

`unlinkat` does not sandbox path traversal. Passing untrusted patch paths directly to it means the patch directory fd only constrains ordinary relative paths. Malicious delete-file paths such as `../target` or absolute paths can delete files outside the package patch directory.

## Fix Requirement

Reject delete-file paths before `unlinkat` when they are empty, absolute, Windows drive-absolute-like, or contain any `..` path component after splitting on recognized separators.

## Patch Rationale

The patch adds validation immediately before the deletion operation in `PatchFile::apply`. It rejects:

- Empty paths.
- Paths beginning with any path separator.
- Windows drive-letter paths such as `C:...`.
- Any path component equal to `..`.

Rejected paths return `EINVAL` for the unlink operation, preventing traversal from reaching `sys::unlinkat`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/patch/lib.rs b/src/patch/lib.rs
index cf2da18873..1845868c12 100644
--- a/src/patch/lib.rs
+++ b/src/patch/lib.rs
@@ -102,6 +102,19 @@ impl<'a> PatchFile<'a> {
         for part in &self.parts {
             match part {
                 PatchFilePart::FileDeletion(file_deletion) => {
+                    if file_deletion.path.is_empty()
+                        || paths::is_sep_any(file_deletion.path[0])
+                        || (file_deletion.path.len() >= 2
+                            && file_deletion.path[1] == b':'
+                            && paths::is_drive_letter(file_deletion.path[0]))
+                        || file_deletion
+                            .path
+                            .split(|b| paths::is_sep_any(*b))
+                            .any(|part| part == b"..")
+                    {
+                        return Some(sys::Error::from_code(sys::E::EINVAL, sys::Tag::unlink));
+                    }
+
                     let pathz = ZBox::from_vec_with_nul(file_deletion.path.to_vec());
 
                     if let sys::Result::Err(e) = sys::unlinkat(patch_dir, &pathz) {
```