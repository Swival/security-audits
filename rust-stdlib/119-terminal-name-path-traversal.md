# Terminal Name Path Traversal

## Classification
Validation gap; medium severity. Confidence: certain.

## Affected Locations
`library/test/src/term/terminfo/searcher.rs:50`

## Summary
`get_dbpath_for_term()` appended the caller-provided terminal name directly to trusted terminfo search directories. Because `PathBuf::push()` accepts absolute paths and parent-directory components, an attacker-controlled terminal name containing path separators could escape the intended terminfo directory and select an arbitrary existing filesystem path.

## Provenance
Verified by Swival Security Scanner: https://swival.dev

## Preconditions
- The caller passes an attacker-controlled terminal name.
- The terminal name contains path separators, an absolute path, or traversal components.
- The targeted escaped path exists on disk.

## Proof
The vulnerable flow was:

- `term` reached `get_dbpath_for_term()` without path validation.
- Only `first_char` was derived from `term`.
- The function entered a trusted terminfo search directory.
- It then performed `p.push(&first_char.to_string())` followed by `p.push(term)`.
- `PathBuf::push(term)` does not confine the result beneath the trusted prefix.
- Absolute `term` values replace the existing prefix.
- `..` components traverse out of the trusted directory.
- `fs::metadata(&p).is_ok()` caused the function to return `Some(p)` for arbitrary existing paths.

A runtime PoC using the committed `searcher.rs` confirmed:

- With `TERMINFO` pointing at a trusted temporary directory, `get_dbpath_for_term("/tmp/.../outside")` returned `Some("/tmp/.../outside")`.
- `get_dbpath_for_term("../outside")` returned `Some(".../trusted/./../outside")`.

The selected path is later opened and parsed as a terminfo entry through `TermInfo::from_name()` and `TermInfo::from_path()`.

## Why This Is A Real Bug
The function is intended to discover terminal database entries beneath configured terminfo directories. The original implementation allowed the untrusted terminal name to alter the path structure rather than act as a single filename. This violates the confinement invariant of the search directory and permits arbitrary existing paths to be selected as terminfo entries.

## Fix Requirement
Reject terminal names that are not exactly one normal path component before appending them with `PathBuf::push()`.

Specifically reject:

- Absolute paths.
- Parent-directory components.
- Current-directory components.
- Prefix components.
- Multi-component paths containing separators.
- Empty paths.

## Patch Rationale
The patch converts `term` to a `Path` and inspects its components before any search path construction:

```rust
let mut components = Path::new(term).components();
match (components.next(), components.next()) {
    (Some(Component::Normal(_)), None) => {}
    _ => return None,
}
```

This permits only a single `Component::Normal(_)` component. Any absolute path, traversal path, separator-containing path, empty path, or otherwise non-normal component returns `None` before `term` is appended to the trusted directory.

The added imports are limited to the validation requirement:

```rust
use std::path::{Component, Path, PathBuf};
```

## Residual Risk
None

## Patch
```diff
diff --git a/library/test/src/term/terminfo/searcher.rs b/library/test/src/term/terminfo/searcher.rs
index 1f9d0bb345b..39a4bdc6446 100644
--- a/library/test/src/term/terminfo/searcher.rs
+++ b/library/test/src/term/terminfo/searcher.rs
@@ -2,7 +2,7 @@
 //!
 //! Does not support hashed database, only filesystem!
 
-use std::path::PathBuf;
+use std::path::{Component, Path, PathBuf};
 use std::{env, fs};
 
 #[cfg(test)]
@@ -12,6 +12,11 @@
 pub(crate) fn get_dbpath_for_term(term: &str) -> Option<PathBuf> {
     let mut dirs_to_search = Vec::new();
     let first_char = term.chars().next()?;
+    let mut components = Path::new(term).components();
+    match (components.next(), components.next()) {
+        (Some(Component::Normal(_)), None) => {}
+        _ => return None,
+    }
 
     // Find search directory
     if let Some(dir) = env::var_os("TERMINFO") {
```