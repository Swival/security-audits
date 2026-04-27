# Interior NUL Truncates Windows chdir Path

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/paths/windows.rs:112`

## Summary

`std` Windows `chdir` converts a `Path` to UTF-16, appends a trailing NUL, and passes the buffer to `SetCurrentDirectoryW`. It did not reject existing interior NUL code units before appending the terminator. Because the Windows API consumes a NUL-terminated `*const u16`, any interior NUL truncates the effective path.

A caller-visible path such as `C:\safe-prefix\0ignored-suffix` can therefore be accepted as `C:\safe-prefix` if the prefix exists.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The caller runs on Windows.
- The caller passes a `Path` containing an interior NUL to `std::env::set_current_dir` / `chdir`.
- The prefix before the interior NUL names an existing directory.

## Proof

In `library/std/src/sys/paths/windows.rs`, `chdir` performed:

```rust
let p: &OsStr = p.as_ref();
let mut p = p.encode_wide().collect::<Vec<_>>();
p.push(0);

cvt(unsafe { c::SetCurrentDirectoryW(p.as_ptr()) }).map(drop)
```

The encoded wide path was only given a trailing terminator. Existing `0` code units were not rejected.

`SetCurrentDirectoryW` receives a NUL-terminated pointer, so it stops at the first NUL. Therefore, an input path containing an interior NUL is interpreted by the OS as only the prefix before that NUL.

The behavior is reachable through standard current-directory changes on Windows, including `std::env::set_current_dir`.

## Why This Is A Real Bug

The caller supplies one logical `Path`, but Windows receives a truncated prefix. If the prefix exists, the operation can succeed while ignoring the suffix that the caller intended to be part of the path.

This is inconsistent with nearby Windows validation patterns in `std`:

- `library/std/src/sys/pal/windows/mod.rs:100` rejects NULs in `to_u16s`.
- `library/std/src/sys/process/windows.rs:917` explicitly uses `ensure_no_nuls(dir)` for process current-directory handling.

The lack of equivalent validation in `chdir` creates a real semantic mismatch and can redirect the process current working directory to an attacker-controlled prefix.

## Fix Requirement

Reject paths whose encoded wide representation contains `0` before appending the terminating NUL and before calling `SetCurrentDirectoryW`.

## Patch Rationale

The patch validates the collected UTF-16 buffer immediately after `encode_wide` and before appending the API terminator:

```rust
if p.contains(&0) {
    return Err(io::const_error!(io::ErrorKind::InvalidInput, "nul byte found in provided data"));
}
```

This preserves valid Windows paths, rejects malformed paths with interior NULs, and aligns `chdir` with existing `std` Windows helpers that treat embedded NULs as `InvalidInput`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/paths/windows.rs b/library/std/src/sys/paths/windows.rs
index cfdc93847a9..c5160aecb69 100644
--- a/library/std/src/sys/paths/windows.rs
+++ b/library/std/src/sys/paths/windows.rs
@@ -106,6 +106,9 @@ pub fn getcwd() -> io::Result<PathBuf> {
 pub fn chdir(p: &path::Path) -> io::Result<()> {
     let p: &OsStr = p.as_ref();
     let mut p = p.encode_wide().collect::<Vec<_>>();
+    if p.contains(&0) {
+        return Err(io::const_error!(io::ErrorKind::InvalidInput, "nul byte found in provided data"));
+    }
     p.push(0);
 
     cvt(unsafe { c::SetCurrentDirectoryW(p.as_ptr()) }).map(drop)
```