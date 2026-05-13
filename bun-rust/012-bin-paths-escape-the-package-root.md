# bin paths escape the package root

## Classification

High severity information disclosure.

## Affected Locations

`src/runtime/cli/pack_command.rs:1516`

## Summary

`bun pack` trusted `package.json` `bin` paths after normalization and did not reject absolute paths or parent-directory traversal. A malicious package could cause a victim running `bun pack` to include victim-readable files outside the package root in the generated tarball.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `bun pack` on an attacker-controlled package.

## Proof

`get_package_bins` accepted `bin` values from `package.json`, normalized them, and stored them as `BinInfo` entries without validating that the resulting path remained inside the package root.

The pack flow then:

- Enqueued every `BinType::File` as an optional `PackQueueItem`.
- Opened queued paths with `bun_sys::openat(root_dir, &item.path, O::RDONLY, 0)`.
- Relied on `openat` with attacker-controlled paths; POSIX `openat` permits `..` traversal and absolute paths to escape the directory fd.
- Wrote the opened file into the archive through `add_archive_entry`.

Relevant reproduced flow:

- `get_package_bins` stores normalized `bin` values at `src/runtime/cli/pack_command.rs:1307` and `src/runtime/cli/pack_command.rs:1322`.
- `pack` enqueues `BinType::File` values at `src/runtime/cli/pack_command.rs:2013`.
- Archive creation opens paths via `openat(root_dir, item.path, O::RDONLY, 0)` at `src/runtime/cli/pack_command.rs:2281`.
- `add_archive_entry` creates the tar pathname from the supplied filename at `src/runtime/cli/pack_command.rs:2796`.
- `add_archive_entry` copies file bytes into the archive at `src/runtime/cli/pack_command.rs:2832`.

Impact: if the targeted outside-root file exists and is readable by the victim, its contents are included in the produced tarball.

## Why This Is A Real Bug

The package author controls `package.json`. The victim supplies filesystem read privileges by running `bun pack`. Because bin paths were treated as package-relative archive inputs without containment validation, an attacker could reference files outside the workspace using `../...` or absolute paths. The archive writer then packaged bytes from those files, disclosing local data to whoever receives or inspects the tarball.

## Fix Requirement

Reject `bin` paths that are absolute or normalize to a path escaping the package root before they are added to the pack queue.

## Patch Rationale

The patch validates normalized `bin` paths in `get_package_bins` before constructing `BinInfo`. It adds `is_invalid_package_bin_path`, which rejects:

- Absolute paths via `path::is_absolute_loose(path)`.
- Paths beginning with `..` or `../`, indicating traversal outside the package root after normalization.

Invalid `bin` entries are skipped, preventing them from being enqueued and later opened by `openat`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/pack_command.rs b/src/runtime/cli/pack_command.rs
index 497239f04d..3a78a128e3 100644
--- a/src/runtime/cli/pack_command.rs
+++ b/src/runtime/cli/pack_command.rs
@@ -1524,10 +1524,12 @@ fn get_package_bins(json: &Expr) -> Result<Vec<BinInfo>, AllocError> {
                 bin_str,
                 &mut path_buf,
             );
-            bins.push(BinInfo {
-                path: ZBox::from_bytes(normalized),
-                ty: BinType::File,
-            });
+            if !is_invalid_package_bin_path(normalized) {
+                bins.push(BinInfo {
+                    path: ZBox::from_bytes(normalized),
+                    ty: BinType::File,
+                });
+            }
             return Ok(bins);
         }
 
@@ -1543,10 +1545,12 @@ fn get_package_bins(json: &Expr) -> Result<Vec<BinInfo>, AllocError> {
                             bin_str,
                             &mut path_buf,
                         );
-                        bins.push(BinInfo {
-                            path: ZBox::from_bytes(normalized),
-                            ty: BinType::File,
-                        });
+                        if !is_invalid_package_bin_path(normalized) {
+                            bins.push(BinInfo {
+                                path: ZBox::from_bytes(normalized),
+                                ty: BinType::File,
+                            });
+                        }
                     }
                 }
             }
@@ -1563,10 +1567,12 @@ fn get_package_bins(json: &Expr) -> Result<Vec<BinInfo>, AllocError> {
                         bin_str,
                         &mut path_buf,
                     );
-                    bins.push(BinInfo {
-                        path: ZBox::from_bytes(normalized),
-                        ty: BinType::Dir,
-                    });
+                    if !is_invalid_package_bin_path(normalized) {
+                        bins.push(BinInfo {
+                            path: ZBox::from_bytes(normalized),
+                            ty: BinType::Dir,
+                        });
+                    }
                 }
             }
         }
@@ -1575,6 +1581,14 @@ fn get_package_bins(json: &Expr) -> Result<Vec<BinInfo>, AllocError> {
     Ok(bins)
 }
 
+fn is_invalid_package_bin_path(path: &[u8]) -> bool {
+    path::is_absolute_loose(path)
+        || (path.len() >= 2
+            && path[0] == b'.'
+            && path[1] == b'.'
+            && (path.len() == 2 || path[2] == b'/'))
+}
+
 fn is_package_bin(bins: &[BinInfo], maybe_bin_path: &[u8]) -> bool {
     for bin in bins {
         match bin.ty {
```