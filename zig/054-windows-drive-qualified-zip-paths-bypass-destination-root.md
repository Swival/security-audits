# Windows Drive-Qualified ZIP Paths Escape Extraction Root

## Classification

Path traversal / arbitrary file creation on Windows.

Severity: Medium.

Confidence: Certain.

## Affected Locations

- `lib/std/zip.zig:209`
- Function: `isBadFilename`
- Call path: `std.zip.extract` → `Iterator.Entry.extract` → `isBadFilename` → `dest.createDirPathOpen` / `createFile`

## Summary

ZIP extraction accepted Windows drive-qualified entry names such as `C:/tmp/pwn`.

The filename validator rejected empty names, leading `/`, backslashes when not allowed, and `..` path components, but did not reject Windows absolute or drive-qualified paths. On Windows, those paths are interpreted outside the supplied destination directory, allowing an attacker-controlled ZIP archive to create files outside the intended extraction root.

## Provenance

Verified by Swival security analysis.

Scanner: [https://swival.dev](https://swival.dev)

## Preconditions

- Extraction runs on Windows.
- The ZIP archive is attacker-controlled.
- The attacker supplies an entry filename such as `C:/tmp/pwn`.
- The target file does not already exist because extraction uses `.exclusive = true`.
- The extracting process has filesystem permissions for the escaped destination.

## Proof

`Entry.extract` reads the central-directory filename into `filename_buf`, normalizes or rejects backslashes, then calls `isBadFilename`.

Before the patch, `isBadFilename` only rejected:

- empty filenames,
- filenames starting with `/`,
- path components equal to `..`.

For `C:/tmp/pwn`:

- it does not start with `/`,
- its `/`-split components are `C:`, `tmp`, and `pwn`,
- none of the components are `..`.

Therefore the filename was accepted.

After validation, extraction calls:

- `std.fs.path.dirname("C:/tmp/pwn")`, which treats the path as Windows drive-absolute and returns `C:/tmp`;
- `dest.createDirPathOpen(io, "C:/tmp", .{})`.

On Windows, the directory creation/open path converts this to an absolute NT path and uses `RootDirectory = null`, so the supplied `dest` directory handle is not used as the containment root. The extractor then creates `pwn` in `C:/tmp`, outside the destination directory.

## Why This Is A Real Bug

The ZIP extraction API is explicitly intended to extract into a caller-provided `dest` directory. Accepting a drive-qualified Windows path violates that containment boundary.

The existing checks prevent common traversal forms such as `../file` and leading `/absolute`, but Windows path syntax has additional absolute forms. `C:/tmp/pwn` bypasses the existing filter and reaches platform filesystem APIs that interpret it as absolute, not relative to `dest`.

This enables practical arbitrary file creation outside the extraction root when processing untrusted ZIP archives on Windows.

## Fix Requirement

Reject Windows absolute, drive-absolute, drive-relative, UNC, or otherwise non-relative paths before creating directories or files.

The validation must happen after backslash normalization/rejection and before any call to `dirname`, `createDirPath`, `createDirPathOpen`, or `createFile`.

## Patch Rationale

The patch adds a Windows-specific check to `isBadFilename`:

```zig
if (builtin.os.tag == .windows and std.fs.path.getWin32PathType(u8, filename) != .relative)
    return true;
```

This uses Zig’s existing Windows path classifier instead of duplicating Windows path parsing rules. Any filename that Windows would not treat as a relative path is rejected before filesystem operations occur.

This blocks `C:/tmp/pwn` and other non-relative Windows path forms while preserving existing behavior for valid relative ZIP entries.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/zip.zig b/lib/std/zip.zig
index be2a442f3d..e73a14792f 100644
--- a/lib/std/zip.zig
+++ b/lib/std/zip.zig
@@ -212,6 +212,9 @@ fn isBadFilename(filename: []const u8) bool {
     if (filename.len == 0 or filename[0] == '/')
         return true;
 
+    if (builtin.os.tag == .windows and std.fs.path.getWin32PathType(u8, filename) != .relative)
+        return true;
+
     var it = std.mem.splitScalar(u8, filename, '/');
     while (it.next()) |part| {
         if (std.mem.eql(u8, part, ".."))
```