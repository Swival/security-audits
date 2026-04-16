# Archive directory entries can escape extraction root

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/miniunz.c:331`
- `contrib/minizip/miniunz.c:358`
- `contrib/minizip/miniunz.c:391`

## Summary
`miniunz` accepts attacker-controlled ZIP entry names when extracting with paths preserved. Its path handling only strips some leading `.` or `/` characters and may rebase on an internal `..`, but it does not reject traversal segments within directory entry paths. As reproduced, a crafted directory entry such as `subdir/../../escapedir/` is passed to `makedir()` and creates directories outside the user-selected extraction root.

## Provenance
- Verified from the supplied reproducer and source inspection in `contrib/minizip/miniunz.c`
- Scanner origin: https://swival.dev

## Preconditions
- Attacker controls a ZIP entry name
- Extraction preserves paths, which is the default behavior in `miniunz`
- The archive contains a crafted directory entry with traversal segments such as `../`

## Proof
The vulnerable flow is in `do_extract_currentfile()`:
- `unzGetCurrentFileInfo64()` copies the entry name into `filename_inzip`
- When path extraction is enabled, `write_filename` is derived from that entry name
- The subsequent sanitization only trims leading `.` and `/` characters and may shift to a later `..` occurrence, but it does not canonicalize or reject embedded `..` path segments in directory names
- For directory entries, the code reaches `makedir(write_filename)` and uses the attacker-controlled traversal path

This was reproduced by building `miniunz` from the repository and extracting a ZIP with `-d extract-root` containing:
- `subdir/`
- `subdir/../../escapedir/`

Observed behavior:
- `miniunz` printed `creating directory: subdir/../../escapedir/`
- The created directory was `/tmp/miniunz_poc2/escapedir`, outside `/tmp/miniunz_poc2/extract-root`

A regular file overwrite via the exact `FOPEN_FUNC(write_filename, "wb")` path was not reproduced on this platform because the later filename rewriting at `contrib/minizip/miniunz.c:358` rebased the tested file path into the extraction root. The confirmed bug is directory traversal through directory entries.

## Why This Is A Real Bug
This is a real path traversal vulnerability because the extractor performs filesystem operations on archive-supplied directory paths without enforcing containment within the intended destination. The reproduced outcome shows attacker-controlled directories are created outside the extraction root, violating the caller's security boundary and enabling follow-on impacts depending on where extraction runs.

## Fix Requirement
Reject archive entry paths that contain `..` path segments after normalization and before any directory creation or file open. Extraction must fail closed for any entry whose resolved path would escape the chosen output directory.

## Patch Rationale
The patch in `007-archive-paths-can-escape-extraction-directory.patch` adds explicit traversal validation to `miniunz` before it calls `makedir()` or opens output paths. This directly addresses the reproduced issue by blocking directory entries with escaping segments instead of attempting partial string rewriting.

## Residual Risk
None

## Patch
```diff
diff --git a/contrib/minizip/miniunz.c b/contrib/minizip/miniunz.c
--- a/contrib/minizip/miniunz.c
+++ b/contrib/minizip/miniunz.c
@@
+static int path_has_dotdot_segment(const char *path)
+{
+    const char *segment = path;
+    const char *p = path;
+
+    while (*p != '\0')
+    {
+        if (*p == '/' || *p == '\\')
+        {
+            if ((p - segment) == 2 && segment[0] == '.' && segment[1] == '.')
+                return 1;
+            segment = p + 1;
+        }
+        p++;
+    }
+
+    if ((p - segment) == 2 && segment[0] == '.' && segment[1] == '.')
+        return 1;
+
+    return 0;
+}
+
@@
-    if ((*write_filename == '.') || (*write_filename == '/'))
+    if ((*write_filename == '.') || (*write_filename == '/'))
     {
         do
         {
             write_filename++;
         } while (*write_filename == '.' || *write_filename == '/');
     }
+
+    if (path_has_dotdot_segment(write_filename))
+    {
+        printf("error: invalid path contains traversal segment: %s\n", filename_inzip);
+        return UNZ_INTERNALERROR;
+    }
```