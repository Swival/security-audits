# drive-only path skips absolutization

## Classification

Logic error, medium severity.

## Affected Locations

`library/std/src/sys/path/windows.rs:106`

## Summary

`get_long_path` promises to return a normalized absolute Windows path, but the short-path optimization returned `C:` unchanged. On Windows, `C:` is drive-relative, not absolute, so callers could pass a drive-relative path through filesystem APIs without the intended `GetFullPathNameW` normalization.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Scanner provenance: https://swival.dev

Confidence: certain.

## Preconditions

- Caller passes a drive-relative path such as `C:` to `get_long_path`.
- The path is converted to null-terminated UTF-16 through `maybe_verbatim` / `to_u16s`.
- The encoded path length is below `LEGACY_MAX_PATH`.

## Proof

The vulnerable branch in `get_long_path` matches the null-terminated UTF-16 form of `C:`:

```rust
[drive, COLON, 0] | [drive, COLON, SEP | ALT_SEP, ..]
    if *drive != SEP && *drive != ALT_SEP =>
{
    return Ok(path);
}
```

For input `C:`, `to_u16s` produces a buffer matching `[drive, COLON, 0]`. Because `path.len() < LEGACY_MAX_PATH`, the branch returns before the later `GetFullPathNameW` call that absolutizes and normalizes paths.

The reproducer confirms this path is reachable through `maybe_verbatim`, which calls `get_long_path(path, true)`, and then through Windows filesystem APIs such as `File::open`.

## Why This Is A Real Bug

`C:` is not absolute in this codebase’s own Windows path model:

- `Prefix::Disk` does not imply a root.
- Windows `is_absolute` requires both a root and a prefix.
- Therefore `C:` is drive-relative, while `C:\...` is absolute.

Returning `C:` unchanged violates the documented invariant of `get_long_path`: “Gets a normalized absolute path that can bypass path length limits.” The existing behavior also allowed Win32 APIs to receive a drive-relative path instead of a frozen, normalized absolute path.

## Fix Requirement

Remove the `[drive, COLON, 0]` early-return case so drive-only paths are passed to `GetFullPathNameW` and converted to normalized absolute paths.

## Patch Rationale

The patch keeps the optimization for already-absolute drive-rooted paths such as `D:\...` and `D:/...`, while excluding drive-only paths such as `D:`.

Before:

```rust
[drive, COLON, 0] | [drive, COLON, SEP | ALT_SEP, ..]
```

After:

```rust
[drive, COLON, SEP | ALT_SEP, ..]
```

This ensures `C:` reaches the existing absolutization logic without changing behavior for absolute drive paths.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/path/windows.rs b/library/std/src/sys/path/windows.rs
index 1c7bf50d190..d6d3500ff2e 100644
--- a/library/std/src/sys/path/windows.rs
+++ b/library/std/src/sys/path/windows.rs
@@ -124,8 +124,7 @@ pub(crate) fn get_long_path(mut path: Vec<u16>, prefer_verbatim: bool) -> io::Re
         match path.as_slice() {
             // Starts with `D:`, `D:\`, `D:/`, etc.
             // Does not match if the path starts with a `\` or `/`.
-            [drive, COLON, 0] | [drive, COLON, SEP | ALT_SEP, ..]
-                if *drive != SEP && *drive != ALT_SEP =>
+            [drive, COLON, SEP | ALT_SEP, ..] if *drive != SEP && *drive != ALT_SEP =>
             {
                 return Ok(path);
             }
```