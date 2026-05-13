# Unbounded Cache Folder Name Copy Panics PackageManager

## Classification

Denial of service via panic. Severity: medium. Confidence: certain.

## Affected Locations

`src/install/PackageManager/PackageManagerDirectories.rs:584`
`src/install/PackageManager/PackageManagerDirectories.rs:630`

## Summary

Git and GitHub cache folder-name formatting copies attacker-controlled `repository.resolved` bytes into a fixed thread-local `PathBuffer` via `ByteCursor::put`. The destination is a safe slice (`buf[at..end].copy_from_slice(bytes)`), so an overlong resolved string panics on slice index out of bounds in release builds, terminating the package manager during install.

## Provenance

Verified and reproduced from Swival.dev Security Scanner findings: https://swival.dev

## Preconditions

- Install processes attacker-controlled git or GitHub resolved metadata.
- The attacker can provide malicious package metadata or a lockfile containing an overlong resolved repository string.
- The victim runs install on that project or lockfile in a release build.

## Proof

`cached_git_folder_name` passes `this.lockfile.str(&repository.resolved)` into `cached_git_folder_name_print`.

`cached_github_folder_name` does the same for GitHub resolutions through `cached_github_folder_name_print`.

Those functions construct a `ByteCursor` over the fixed thread-local buffer returned by `cached_package_folder_name_buf()`. The cursor then writes prefix bytes and the full attacker-controlled `resolved` byte slice.

`ByteCursor::put` computes `end = self.at + bytes.len()` and then does `self.buf[self.at..end].copy_from_slice(bytes)`. Both `addition` (in debug) and slice indexing (in release) panic when `end > buf.len()`. An overlong attacker-controlled resolved string therefore aborts the package manager process during install.

The reproduced path reaches this during install through `cached_git_folder_name` / `cached_github_folder_name` callers in `PackageInstaller.rs`, `isolated_install.rs`, and `extract_tarball.rs`.

## Why This Is A Real Bug

The input is attacker-controlled lockfile or package metadata, not an internal invariant. The destination is a fixed-size path buffer. The vulnerable code formats unbounded resolved repository strings into that buffer before NUL termination. While Rust's safe slice indexing prevents memory corruption, it converts oversized input into a panic that aborts the package manager, providing a deterministic attacker-triggered denial of service against any user installing the malicious package or lockfile.

## Fix Requirement

Git and GitHub cache folder-name construction must not copy unbounded resolved metadata into `PathBuffer`. Overlong values must be rejected, truncated safely, or converted to a bounded representation such as a hash before writing.

## Patch Rationale

The patch bounds the Git and GitHub resolved-name payload before writing. It computes the worst-case formatted length, including prefixes, cache-version text, patch-hash suffix space, and NUL headroom by requiring the computed length to remain below `buf.len()`.

If the resolved string is too long, the formatter writes a fixed 16-hex hash of the resolved bytes instead of copying the full attacker-controlled string. Normal-length resolved strings preserve existing cache folder names.

This keeps the output deterministic, bounded, and compatible with the existing `ByteCursor` formatting flow.

## Residual Risk

None

## Patch

```diff
diff --git a/src/install/PackageManager/PackageManagerDirectories.rs b/src/install/PackageManager/PackageManagerDirectories.rs
index 571ef1238f..4d45270e37 100644
--- a/src/install/PackageManager/PackageManagerDirectories.rs
+++ b/src/install/PackageManager/PackageManagerDirectories.rs
@@ -586,9 +586,19 @@ pub fn cached_git_folder_name_print<'a>(
     resolved: &[u8],
     patch_hash: Option<u64>,
 ) -> &'a ZStr {
+    let resolved_too_long = resolved
+        .len()
+        .saturating_add(b"@G@".len())
+        .saturating_add(b"_patch_hash=".len())
+        .saturating_add(16)
+        >= buf.len();
     let mut w = ByteCursor::new(buf);
     w.put(b"@G@");
-    w.put(resolved);
+    if resolved_too_long {
+        w.put_u64_hex16::<true>(Semver::semver_string::Builder::string_hash(resolved));
+    } else {
+        w.put(resolved);
+    }
     w.put_patch_hash(patch_hash);
     w.finish_z()
 }
@@ -632,9 +642,21 @@ pub fn cached_github_folder_name_print<'a>(
     resolved: &[u8],
     patch_hash: Option<u64>,
 ) -> &'a ZStr {
+    let resolved_too_long = resolved
+        .len()
+        .saturating_add(b"@GH@".len())
+        .saturating_add(b"@@@".len())
+        .saturating_add(20)
+        .saturating_add(b"_patch_hash=".len())
+        .saturating_add(16)
+        >= buf.len();
     let mut w = ByteCursor::new(buf);
     w.put(b"@GH@");
-    w.put(resolved);
+    if resolved_too_long {
+        w.put_u64_hex16::<true>(Semver::semver_string::Builder::string_hash(resolved));
+    } else {
+        w.put(resolved);
+    }
     w.put_cache_version(Some(CacheVersion::CURRENT));
     w.put_patch_hash(patch_hash);
     w.finish_z()
```