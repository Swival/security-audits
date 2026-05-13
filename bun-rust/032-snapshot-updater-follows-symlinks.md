# Snapshot Updater Follows Symlinks

## Classification

Path traversal / symlink-following file overwrite.

Severity: High.

Confidence: Certain.

## Affected Locations

- `src/runtime/test_runner/snapshot.rs:895`
- `src/runtime/test_runner/snapshot.rs:921`
- `src/runtime/test_runner/snapshot.rs:925`
- `src/runtime/test_runner/snapshot.rs:334`

## Summary

The snapshot updater constructs a snapshot path under `__snapshots__` and, when `--update-snapshots` is enabled, opens it with `O_CREAT | O_RDWR | O_TRUNC` without symlink protection. An attacker who can modify the project can commit a symlinked snapshot directory or final snapshot file, causing a trusted user running tests with `--update-snapshots` to truncate and write an arbitrary symlink target with the runner user's privileges.

## Provenance

Identified by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied evidence.

## Preconditions

- A trusted user runs tests with `--update-snapshots`.
- The project tree is attacker-modifiable, such as through a lower-privileged contributor commit.
- The attacker can place a symlink at the snapshot directory path or final snapshot file path.

## Proof

`get_snapshot_file` builds the snapshot path from:

- the test file directory,
- `__snapshots__/`,
- the test filename,
- `.snap`.

When the snapshot directory already exists, `mkdir` treats `EEXIST` as acceptable without verifying the existing path is a real directory. The updater then opens the final snapshot file with `O_CREAT | O_RDWR`, and adds `O_TRUNC` when `update_snapshots` is true.

Because the open call does not use `O_NOFOLLOW`, a symlink at the final snapshot path is followed. Because the directory existence path does not reject symlinks or non-directories, a symlinked `__snapshots__` path can redirect snapshot writes outside the intended project directory.

The reproduced impact is outside-project truncation and write:

- `O_TRUNC` truncates the symlink target during snapshot update.
- `write_snapshot_file` later writes snapshot contents to the opened target.

## Why This Is A Real Bug

The behavior crosses a trust boundary between attacker-controlled project files and trusted-user filesystem privileges. Snapshot updates are expected to modify generated snapshot files inside the project, not follow attacker-controlled symlinks to arbitrary filesystem targets.

The exact `__snapshots__` symlink-to-file variant fails because the implementation appends `/<filename>.snap`, but the vulnerability remains valid through either:

- a symlinked snapshot directory, or
- a symlink at the final snapshot file path.

Both variants are sufficient to cause truncation and write outside the intended snapshot location.

## Fix Requirement

Snapshot updates must not follow symlinks and must reject unexpected filesystem object types.

Required behavior:

- Reject an existing snapshot directory path unless it is a real directory.
- Open snapshot files with `O_NOFOLLOW`.
- After opening, verify the file descriptor refers to a regular file.
- Close the file descriptor on validation failure.

## Patch Rationale

The patch hardens both path components involved in the exploit.

For the snapshot directory:

- On `mkdir` `EEXIST`, the code now calls `lstat`.
- It accepts the path only when `lstat` reports `FileKind::Directory`.
- It rejects other object types with `ENOTDIR`.

For the snapshot file:

- The open flags now include `O_NOFOLLOW`.
- After opening, the code calls `fstat`.
- It accepts only regular files.
- It closes the descriptor and returns an error for non-regular files or failed `fstat`.

This prevents both symlink-following at open time and writes to non-regular objects.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/test_runner/snapshot.rs b/src/runtime/test_runner/snapshot.rs
index 66e7cb0ebb..8b461ba471 100644
--- a/src/runtime/test_runner/snapshot.rs
+++ b/src/runtime/test_runner/snapshot.rs
@@ -901,10 +901,19 @@ impl<'a> Snapshots<'a> {
                         self.snapshot_dir_path = Some(core::ptr::NonNull::from(dir_path));
                     }
                     bun_sys::Result::Err(err) => match err.get_errno() {
-                        bun_sys::Errno::EEXIST => {
-                            // SAFETY: see above — read-only backref, never written through.
-                            self.snapshot_dir_path = Some(core::ptr::NonNull::from(dir_path));
-                        }
+                        bun_sys::Errno::EEXIST => match bun_sys::lstat(snapshot_dir_path) {
+                            Ok(st) if bun_sys::kind_from_mode(st.st_mode as bun_sys::Mode) == bun_sys::FileKind::Directory => {
+                                // SAFETY: see above — read-only backref, never written through.
+                                self.snapshot_dir_path = Some(core::ptr::NonNull::from(dir_path));
+                            }
+                            Ok(_) => {
+                                return Ok(bun_sys::Result::Err(
+                                    bun_sys::Error::from_code(bun_sys::E::ENOTDIR, bun_sys::Tag::mkdir)
+                                        .with_path(snapshot_dir_path.as_bytes()),
+                                ));
+                            }
+                            Err(err) => return Ok(bun_sys::Result::Err(err)),
+                        },
                         _ => return Ok(bun_sys::Result::Err(err)),
                     },
                 }
@@ -918,7 +927,7 @@ impl<'a> Snapshots<'a> {
             // SAFETY: buf[pos] == 0 written above
             let snapshot_file_path = ZStr::from_buf(&buf[..], pos);
 
-            let mut flags: i32 = bun_sys::O::CREAT | bun_sys::O::RDWR;
+            let mut flags: i32 = bun_sys::O::CREAT | bun_sys::O::RDWR | bun_sys::O::NOFOLLOW;
             if self.update_snapshots {
                 flags |= bun_sys::O::TRUNC;
             }
@@ -926,6 +935,20 @@ impl<'a> Snapshots<'a> {
                 bun_sys::Result::Ok(fd) => fd,
                 bun_sys::Result::Err(err) => return Ok(bun_sys::Result::Err(err)),
             };
+            match bun_sys::fstat(fd) {
+                Ok(st) if bun_sys::is_regular_file(st.st_mode as bun_sys::Mode) => {}
+                Ok(_) => {
+                    let _ = bun_sys::close(fd);
+                    return Ok(bun_sys::Result::Err(
+                        bun_sys::Error::from_code(bun_sys::E::EINVAL, bun_sys::Tag::open)
+                            .with_path(snapshot_file_path.as_bytes()),
+                    ));
+                }
+                Err(err) => {
+                    let _ = bun_sys::close(fd);
+                    return Ok(bun_sys::Result::Err(err));
+                }
+            }
 
             let file = File {
                 id: file_id,
```