# Archive paths can escape extraction directory

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/miniunz.c:331`
- `contrib/minizip/miniunz.c:358`
- `contrib/minizip/miniunz.c:417`

## Summary
`miniunz` accepts ZIP entry names with traversal segments when extracting with paths preserved. In the reproduced case, directory entries such as `subdir/../../escapedir/` are passed through path handling and reach `makedir(write_filename)`, allowing directory creation outside the user-selected extraction root.

## Provenance
- Verified from the supplied finding and local reproduction evidence
- Scanner origin: https://swival.dev

## Preconditions
- Attacker controls a ZIP entry name
- Extraction preserves archive paths, which is the default behavior in `do_extract_currentfile()`
- The archive contains a directory entry with `..` path segments

## Proof
- `unzGetCurrentFileInfo64()` copies the entry name into `filename_inzip`, and path-preserving extraction keeps that path in `write_filename`
- Existing sanitization only strips leading `.` or `/` and may rebase around one internal `..`, but does not reject traversal segments in the full path
- Reproduction built `miniunz` from the committed sources and extracted a ZIP with `-d extract-root` containing `subdir/` and `subdir/../../escapedir/`
- The extractor logged `creating directory: subdir/../../escapedir/`
- The created directory appeared at `/tmp/miniunz_poc2/escapedir`, outside `/tmp/miniunz_poc2/extract-root`

## Why This Is A Real Bug
The extraction root is a security boundary. Creating attacker-chosen directories outside that boundary is a filesystem traversal vulnerability even when the demonstrated impact is directory creation rather than arbitrary file overwrite. The behavior is reachable in default path-preserving extraction and is controlled solely by archive metadata.

## Fix Requirement
Reject entry paths that contain `..` traversal segments after normalization and before any directory creation or file open operation.

## Patch Rationale
The patch in `007-archive-paths-can-escape-extraction-directory.patch` hardens `contrib/minizip/miniunz.c` by validating normalized archive paths before they are used. This blocks traversal-bearing directory entries from reaching `makedir()` and prevents extraction from escaping the requested destination.

## Residual Risk
None

## Patch
`007-archive-paths-can-escape-extraction-directory.patch`