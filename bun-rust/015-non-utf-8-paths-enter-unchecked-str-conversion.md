# Non-UTF-8 Paths Enter Unchecked str Conversion

## Classification

High severity memory corruption.

Confidence: certain.

## Affected Locations

- `src/bun_core/fmt.rs:621`
- `src/bun_core/fmt.rs:632`
- `src/bun_core/fmt.rs:640`
- `src/bun_core/fmt.rs:3532` (`write_bytes` definition / `from_utf8_unchecked` sink)

## Summary

On non-Windows builds, `fmt_os_path` aliases `FormatOSPath` to `FormatUTF8` and formats raw `OSPathSlice` bytes. When path formatting options are present, `FormatUTF8::fmt` writes either the full buffer or path chunks through `write_bytes`. `write_bytes` uses `core::str::from_utf8_unchecked(bytes)` before calling `write_str`, so attacker-controlled POSIX filenames containing invalid UTF-8 violate Rust’s `str` validity invariant.

The patch changes the path-formatting branches to use `bstr::BStr::new(...)`, which safely renders arbitrary byte paths without constructing an invalid `&str`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Non-Windows build.
- Attacker can influence filesystem path bytes.
- A non-UTF-8 path is formatted through `fmt_os_path` with path formatting options.

## Proof

The reproduced path is:

- On non-Windows, `FormatOSPath<'a>` is `FormatUTF8<'a>`.
- `fmt_os_path` stores raw `OSPathSlice` bytes in `FormatUTF8 { buf, path_fmt_opts: Some(options) }`.
- `FormatUTF8::fmt` previously called `write_bytes` for path formatting:
  - full-buffer path when `path_sep == PathSep::Any && !escape_backslashes`
  - separator-delimited chunks before each rewritten separator
  - final remaining chunk
- `write_bytes` calls `core::str::from_utf8_unchecked(bytes)` and then `write_str`.
- A byte sequence such as `b"\xff"` is invalid UTF-8 but can be a valid POSIX filename byte sequence.
- Reachability was reproduced from raw directory walking names stored into `OSPathSliceZ` and later formatted through install/copy error paths.

## Why This Is A Real Bug

Rust requires every `&str` to contain valid UTF-8. Calling `from_utf8_unchecked` on attacker-controlled path bytes such as `b"\xff"` deterministically creates an invalid `&str`. This is immediate undefined behavior because the Rust validity invariant is violated before any downstream formatter behavior is considered.

This is not only display corruption: POSIX permits non-UTF-8 filenames, and the affected formatting path accepts raw filesystem bytes.

## Fix Requirement

Path formatting for raw OS path bytes must not call `from_utf8_unchecked` unless validity is guaranteed. It must either validate UTF-8 first or use a byte-safe/lossy formatter for arbitrary bytes.

## Patch Rationale

The patch replaces the unsafe path-formatting writes with `bstr::BStr::new(...)` in the branches that process `FormatUTF8` with `path_fmt_opts`.

`BStr` formats arbitrary byte slices safely by handling invalid UTF-8 instead of constructing an invalid `&str`. Separator normalization and backslash escaping behavior remains intact because only the chunk emission mechanism changes.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bun_core/fmt.rs b/src/bun_core/fmt.rs
index 2d6530e07b..a5289c7ebe 100644
--- a/src/bun_core/fmt.rs
+++ b/src/bun_core/fmt.rs
@@ -618,7 +618,7 @@ impl Display for FormatUTF8<'_> {
     fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
         if let Some(opts) = self.path_fmt_opts {
             if opts.path_sep == PathSep::Any && !opts.escape_backslashes {
-                return write_bytes(f, self.buf);
+                return write!(f, "{}", bstr::BStr::new(self.buf));
             }
 
             let mut ptr = self.buf;
@@ -629,7 +629,7 @@ impl Display for FormatUTF8<'_> {
                     PathSep::Auto => crate::SEP,
                     PathSep::Any => ptr[i],
                 };
-                write_bytes(f, &ptr[..i])?;
+                write!(f, "{}", bstr::BStr::new(&ptr[..i]))?;
                 f.write_char(sep as char)?;
                 if opts.escape_backslashes && sep == b'\\' {
                     f.write_char(sep as char)?;
@@ -637,7 +637,7 @@ impl Display for FormatUTF8<'_> {
                 ptr = &ptr[i + 1..];
             }
 
-            return write_bytes(f, ptr);
+            return write!(f, "{}", bstr::BStr::new(ptr));
         }
 
         write_bytes(f, self.buf)
```