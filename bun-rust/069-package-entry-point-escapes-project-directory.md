# Package Entry Point Escapes Project Directory

## Classification

Path traversal. Severity: medium. Confidence: certain.

## Affected Locations

`src/runtime/cli/init_command.rs:861`

## Summary

`bun init` trusted a string-valued `package.json` `module` or `main` entry point and later used it for filesystem creation. If the entry point contained parent-directory components such as `../outside/file.js`, init created directories and a generated starter file outside the project directory.

## Provenance

Verified from the supplied source, reproduced behavior, and patch. Originally identified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

Victim runs init in a repository whose `package.json` references a missing entry point.

## Proof

A malicious repository can include:

```json
{
  "module": "../outside/file.js"
}
```

Execution path:

- `package.json` parsing assigns the attacker-controlled string directly to `fields.entry_point`.
- The Blank/TypescriptLibrary path checks only `!exists(&fields.entry_point)`.
- For `../outside/file.js`, the existence check is performed against the escaped path.
- `dirname(&fields.entry_point)` yields `../outside`.
- `bun_sys::make_path(bun_sys::Dir::cwd(), dirname)` creates `../outside` relative to the project cwd.
- `Assets::create_new` receives the same entry point and calls `File::openat(Fd::cwd(), filename.as_bytes(), O::CREAT | O::EXCL | O::WRONLY)`.
- No prior component rejects `..`, so the generated Bun starter content is written to `../outside/file.js`.

`O_EXCL` prevents overwriting an existing file, but it still permits attacker-controlled file creation outside the intended project boundary.

## Why This Is A Real Bug

The command boundary is the project directory, but the entry point from `package.json` is attacker-controlled repository data. Because the code allowed parent-directory components and absolute-style paths through to `make_path` and `openat`, a repository author could cause `bun init` to create attacker-named files and directories outside the project. This is a filesystem write outside the intended destination, not just incorrect metadata handling.

## Fix Requirement

Reject unsafe entry point paths before any filesystem use. At minimum, disallow absolute paths and any path component equal to `..` across both Unix and Windows separators.

## Patch Rationale

The patch adds `is_safe_entry_point_path` and gates starter entry-point creation on it:

```rust
if !fields.entry_point.is_empty()
    && is_safe_entry_point_path(&fields.entry_point)
    && !exists(&fields.entry_point)
```

The helper rejects:

- absolute paths via `bun_paths::is_absolute_loose(path)`;
- parent-directory traversal by splitting on `/` and `\`;
- any component exactly equal to `..`.

This prevents `make_path` and `Assets::create_new` from operating on escaped entry point paths while preserving normal relative entry points such as `index.ts` and `src/index.ts`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/cli/init_command.rs b/src/runtime/cli/init_command.rs
index f6715659d5..f615d7e1b4 100644
--- a/src/runtime/cli/init_command.rs
+++ b/src/runtime/cli/init_command.rs
@@ -879,7 +879,10 @@ impl InitCommand {
                     Output::flush();
                 }
 
-                if !fields.entry_point.is_empty() && !exists(&fields.entry_point) {
+                if !fields.entry_point.is_empty()
+                    && is_safe_entry_point_path(&fields.entry_point)
+                    && !exists(&fields.entry_point)
+                {
                     if let Some(dirname) = bun_core::dirname(&fields.entry_point) {
                         if dirname != b"." {
                             let _ = bun_sys::make_path(bun_sys::Dir::cwd(), dirname);
@@ -2016,6 +2019,13 @@ pub(crate) fn exists(path: &[u8]) -> bool {
     bun_sys::exists(path)
 }
 
+fn is_safe_entry_point_path(path: &[u8]) -> bool {
+    !bun_paths::is_absolute_loose(path)
+        && !path
+            .split(|&c| c == b'/' || c == b'\\')
+            .any(|component| component == b"..")
+}
+
 #[inline]
 fn exists_z(path: &[u8]) -> bool {
     // TODO(port): Zig `existsZ` takes `[:0]const u8`; here we accept `&[u8]` and
```