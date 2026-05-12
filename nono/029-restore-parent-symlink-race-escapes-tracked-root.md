# Restore parent symlink race escapes tracked root

## Classification

Path traversal / time-of-check-time-of-use filesystem race.

Severity: medium.

Confidence: certain.

## Affected Locations

`crates/nono/src/undo/snapshot.rs:278`

## Summary

`SnapshotManager::restore_to` validated restore targets before writing, but later performed `create_dir_all`, object retrieval, temp-file creation, rename, and chmod using path-based APIs. An attacker able to race filesystem changes under a tracked directory could replace a previously validated parent directory with a symlink after validation and before restore writes, causing restored content or directories to be created outside the tracked root.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- The attacker can race filesystem changes during restore of a needed file.
- The attacker controls or can influence a malicious filesystem backend for a tracked directory.
- A restore operation writes a file whose parent path was validated before the race.

## Proof

The vulnerable flow was:

1. `restore_to` called `validate_manifest_paths`.
2. `restore_to` computed current filesystem state.
3. For each needed manifest file, `restore_to` called `validate_restore_target`, which used `symlink_metadata` to reject symlinked tracked roots and existing parent components.
4. After all validations completed, `restore_to` reused the same path strings for `fs::create_dir_all`, `self.object_store.retrieve_to`, and `fs::set_permissions`.

`ObjectStore::retrieve_to` then performed path-based temp-file creation and rename through `target.parent()` at `crates/nono/src/undo/object_store.rs:102`, `crates/nono/src/undo/object_store.rs:114`, `crates/nono/src/undo/object_store.rs:120`, and `crates/nono/src/undo/object_store.rs:146`.

A malicious backend can make `/tracked/subdir` appear as a real directory during `validate_restore_target`, then swap `/tracked/subdir` to a symlink to `/outside` before `create_dir_all` or `retrieve_to`. The restore then writes `/outside/<file>` with snapshot-controlled content and may chmod it.

## Why This Is A Real Bug

The existing checks only rejected symlinks present at validation time. They did not bind the validated parent directory to the later write operations.

Because later operations resolved paths again, the parent component could change between check and use. This gives an attacker with filesystem race capability a concrete integrity impact: writing restored files and creating directories outside the tracked root as the restoring user.

## Fix Requirement

Restore must write relative to validated directory file descriptors and must not follow symlinked parent components. Parent creation and traversal must use `openat`/`mkdirat`-style APIs with `O_NOFOLLOW`, and the final file write/rename must occur relative to the already-open parent directory descriptor.

## Patch Rationale

The patch replaces the vulnerable restore write sequence with `restore_file_no_follow`.

Key changes:

- Selects the longest matching tracked root and derives the target parent and leaf name.
- Opens the tracked root with `open(..., O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`.
- Walks each relative parent component using `openat(..., O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)`.
- Creates missing parent directories with `mkdirat`, then reopens them with `O_NOFOLLOW`.
- Retrieves object content into memory and verifies its SHA-256 hash before writing.
- Writes the restored file to a temporary file with `openat` relative to the validated parent fd.
- Applies permissions via `fchmod` on the temp file, masking to `0o0777`.
- Atomically installs the restored file with `renameat` relative to the same parent fd.
- Cleans up the temp file with `unlinkat` on write or rename failure.

This removes the exploitable gap between parent validation and path-based writes because restore operations no longer re-resolve attacker-controlled parent paths after validation.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/undo/snapshot.rs b/crates/nono/src/undo/snapshot.rs
index 5bf3773..272d208 100644
--- a/crates/nono/src/undo/snapshot.rs
+++ b/crates/nono/src/undo/snapshot.rs
@@ -7,9 +7,12 @@
 use crate::error::{NonoError, Result};
 use sha2::{Digest, Sha256};
 use std::collections::{HashMap, HashSet};
+use std::ffi::{CStr, CString};
 use std::fs;
-use std::io::Read;
+use std::io::{Read, Write};
+use std::os::unix::ffi::OsStrExt;
 use std::os::unix::fs::MetadataExt;
+use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
 use std::path::{Path, PathBuf};
 use walkdir::WalkDir;
 
@@ -277,27 +280,7 @@ impl SnapshotManager {
             };
 
             if needs_restore {
-                // Ensure parent directory exists
-                if let Some(parent) = path.parent() {
-                    fs::create_dir_all(parent).map_err(|e| {
-                        NonoError::Snapshot(format!(
-                            "Failed to create directory {}: {e}",
-                            parent.display()
-                        ))
-                    })?;
-                }
-
-                self.object_store.retrieve_to(&state.hash, path)?;
-
-                // Restore permissions (mask out setuid/setgid/sticky bits)
-                #[cfg(unix)]
-                {
-                    use std::os::unix::fs::PermissionsExt;
-                    let perms = fs::Permissions::from_mode(state.permissions & 0o0777);
-                    if let Err(e) = fs::set_permissions(path, perms) {
-                        tracing::warn!("Failed to set permissions on {}: {}", path.display(), e);
-                    }
-                }
+                self.restore_file_no_follow(path, state)?;
 
                 let change_type = if current_files.contains_key(path) {
                     ChangeType::Modified
@@ -651,6 +634,51 @@ impl SnapshotManager {
         Ok(())
     }
 
+    fn restore_file_no_follow(&self, path: &Path, state: &FileState) -> Result<()> {
+        let tracked = self
+            .tracked_paths
+            .iter()
+            .filter(|tracked| path.starts_with(tracked))
+            .max_by_key(|tracked| tracked.components().count())
+            .ok_or_else(|| {
+                NonoError::Snapshot(format!(
+                    "Manifest contains path outside tracked directories: {}",
+                    path.display()
+                ))
+            })?;
+        let parent = path.parent().ok_or_else(|| {
+            NonoError::Snapshot(format!("Restore target has no parent: {}", path.display()))
+        })?;
+        let leaf = path.file_name().ok_or_else(|| {
+            NonoError::Snapshot(format!("Restore target has no file name: {}", path.display()))
+        })?;
+        let leaf = cstring_from_component(leaf)?;
+
+        let parent_dir = if tracked == path {
+            open_dir_nofollow(parent)?
+        } else {
+            let relative_parent = parent.strip_prefix(tracked).map_err(|_| {
+                NonoError::Snapshot(format!(
+                    "Restore target parent {} is outside tracked root {}",
+                    parent.display(),
+                    tracked.display()
+                ))
+            })?;
+            open_restore_parent(tracked, relative_parent)?
+        };
+
+        let content = self.object_store.retrieve(&state.hash)?;
+        let actual: [u8; 32] = Sha256::digest(&content).into();
+        if actual != *state.hash.as_bytes() {
+            return Err(NonoError::Snapshot(format!(
+                "Object integrity check failed for {}: content hash mismatch",
+                state.hash
+            )));
+        }
+
+        write_restored_file_at(parent_dir.as_raw_fd(), &leaf, path, &content, state.permissions)
+    }
+
     /// Walk tracked paths and store all non-excluded files in the object store.
     ///
     /// Permission errors on individual files are logged and skipped rather than
@@ -861,6 +889,178 @@ impl SnapshotManager {
     }
 }
 
+fn cstring_from_component(component: &std::ffi::OsStr) -> Result<CString> {
+    CString::new(component.as_bytes()).map_err(|_| {
+        NonoError::Snapshot(format!(
+            "Restore path component contains interior NUL: {}",
+            component.to_string_lossy()
+        ))
+    })
+}
+
+fn path_cstring(path: &Path) -> Result<CString> {
+    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
+        NonoError::Snapshot(format!(
+            "Restore path contains interior NUL: {}",
+            path.display()
+        ))
+    })
+}
+
+fn open_restore_parent(tracked: &Path, relative_parent: &Path) -> Result<fs::File> {
+    let mut dir = open_dir_nofollow(tracked)?;
+    let mut display = tracked.to_path_buf();
+
+    for component in relative_parent.components() {
+        match component {
+            std::path::Component::CurDir => continue,
+            std::path::Component::Normal(name) => {
+                let name = cstring_from_component(name)?;
+                display.push(CStr::to_string_lossy(&name).as_ref());
+                match open_dir_at(dir.as_raw_fd(), &name) {
+                    Ok(next) => dir = next,
+                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
+                        mkdir_at(dir.as_raw_fd(), &name, &display)?;
+                        dir = open_dir_at(dir.as_raw_fd(), &name).map_err(|e| {
+                            NonoError::Snapshot(format!(
+                                "Failed to open created restore directory {} without following symlinks: {e}",
+                                display.display()
+                            ))
+                        })?;
+                    }
+                    Err(e) => {
+                        return Err(NonoError::Snapshot(format!(
+                            "Failed to open restore parent {} without following symlinks: {e}",
+                            display.display()
+                        )));
+                    }
+                }
+            }
+            _ => {
+                return Err(NonoError::Snapshot(format!(
+                    "Restore target contains unsupported path component: {}",
+                    relative_parent.display()
+                )));
+            }
+        }
+    }
+
+    Ok(dir)
+}
+
+fn open_dir_nofollow(path: &Path) -> Result<fs::File> {
+    let path = path_cstring(path)?;
+    let fd = unsafe {
+        libc::open(
+            path.as_ptr(),
+            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
+        )
+    };
+    if fd < 0 {
+        return Err(NonoError::Snapshot(format!(
+            "Failed to open tracked restore root without following symlinks: {}",
+            std::io::Error::last_os_error()
+        )));
+    }
+    Ok(unsafe { fs::File::from_raw_fd(fd) })
+}
+
+fn open_dir_at(parent_fd: RawFd, name: &CStr) -> std::io::Result<fs::File> {
+    let fd = unsafe {
+        libc::openat(
+            parent_fd,
+            name.as_ptr(),
+            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
+        )
+    };
+    if fd < 0 {
+        return Err(std::io::Error::last_os_error());
+    }
+    Ok(unsafe { fs::File::from_raw_fd(fd) })
+}
+
+fn mkdir_at(parent_fd: RawFd, name: &CStr, display: &Path) -> Result<()> {
+    let ret = unsafe { libc::mkdirat(parent_fd, name.as_ptr(), 0o777) };
+    if ret < 0 {
+        let e = std::io::Error::last_os_error();
+        if e.kind() != std::io::ErrorKind::AlreadyExists {
+            return Err(NonoError::Snapshot(format!(
+                "Failed to create restore directory {}: {e}",
+                display.display()
+            )));
+        }
+    }
+    Ok(())
+}
+
+fn write_restored_file_at(
+    parent_fd: RawFd,
+    leaf: &CStr,
+    path: &Path,
+    content: &[u8],
+    permissions: u32,
+) -> Result<()> {
+    let temp_name = CString::new(format!(
+        ".nono-restore-{}-{:08x}",
+        std::process::id(),
+        super::object_store::random_u32()
+    ))
+    .expect("restore temp name has no NUL");
+
+    let temp_fd = unsafe {
+        libc::openat(
+            parent_fd,
+            temp_name.as_ptr(),
+            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_CLOEXEC,
+            0o600,
+        )
+    };
+    if temp_fd < 0 {
+        return Err(NonoError::Snapshot(format!(
+            "Failed to create restore temp file for {}: {}",
+            path.display(),
+            std::io::Error::last_os_error()
+        )));
+    }
+
+    let mut temp_file = unsafe { fs::File::from_raw_fd(temp_fd) };
+    let write_result = (|| -> Result<()> {
+        temp_file.write_all(content).map_err(|e| {
+            NonoError::Snapshot(format!("Failed to write restore temp file for {}: {e}", path.display()))
+        })?;
+        let mode = permissions & 0o0777;
+        if unsafe { libc::fchmod(temp_file.as_raw_fd(), mode as libc::mode_t) } < 0 {
+            tracing::warn!(
+                "Failed to set permissions on restore temp for {}: {}",
+                path.display(),
+                std::io::Error::last_os_error()
+            );
+        }
+        temp_file.sync_all().map_err(|e| {
+            NonoError::Snapshot(format!("Failed to sync restore temp file for {}: {e}", path.display()))
+        })?;
+        Ok(())
+    })();
+
+    drop(temp_file);
+
+    if let Err(e) = write_result {
+        let _ = unsafe { libc::unlinkat(parent_fd, temp_name.as_ptr(), 0) };
+        return Err(e);
+    }
+
+    if unsafe { libc::renameat(parent_fd, temp_name.as_ptr(), parent_fd, leaf.as_ptr()) } < 0 {
+        let e = std::io::Error::last_os_error();
+        let _ = unsafe { libc::unlinkat(parent_fd, temp_name.as_ptr(), 0) };
+        return Err(NonoError::Snapshot(format!(
+            "Failed to rename restore temp file to {}: {e}",
+            path.display()
+        )));
+    }
+
+    Ok(())
+}
+
 /// Compute changes between two snapshot file maps.
 fn compute_changes(
     previous: &HashMap<PathBuf, FileState>,
```