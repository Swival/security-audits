# Failed Temp Open Schedules Unowned Path Deletion

## Classification

resource lifecycle bug; severity medium; confidence certain

## Affected Locations

`modules/dav/fs/repos.c:707`

## Summary

`DAV_MODE_WRITE_TRUNC` creates a mutable temporary pathname and calls `dav_fs_mktemp()`. If `dav_fs_mktemp()` fails, the original code still registers `tmpfile_cleanup` before checking `rv`. `dav_fs_open_stream()` then returns an error, but request-pool cleanup later calls `tmpfile_cleanup`, which removes `ds->temppath` even though no temp file was successfully created or owned.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- Filesystem repository `open_stream` is reached for a truncating write.
- Mode is `DAV_MODE_WRITE_TRUNC`.
- `dav_fs_mktemp()` returns a non-success status other than the handled `EEXIST` retry path, such as `EMFILE`, `ENOSPC`, or `EACCES`.
- The mutated candidate temp path exists by the time request-pool cleanup runs.

## Proof

- In `DAV_MODE_WRITE_TRUNC`, `ds->temppath` is built from the requested resource directory with prefix `.davfs.tmpXXXXXX`.
- `dav_fs_mktemp()` mutates the trailing `XXXXXX` template before returning.
- On a non-success result, no temp file is guaranteed to have been created or owned.
- The original code still calls `apr_pool_cleanup_register(p, ds, tmpfile_cleanup, apr_pool_cleanup_null)` immediately after `dav_fs_mktemp()`.
- `dav_fs_open_stream()` then detects `rv != APR_SUCCESS` and returns an error without returning the stream and without killing the registered cleanup.
- Later request-pool destruction invokes `tmpfile_cleanup`.
- `tmpfile_cleanup` only checks `ds->temppath` is non-null, then calls `apr_file_remove(ds->temppath, ds->p)`.
- Therefore cleanup can unlink a file at the mutated temp pathname that was not created by this failed open.

## Why This Is A Real Bug

The cleanup ownership invariant is violated. Cleanup for a temporary file is registered even when temporary-file creation failed. Because the cleanup removes by pathname rather than by a proven-owned file handle, any file occupying the mutated `.davfs.tmpXXXXXX` pathname before pool cleanup can be deleted. This is reachable through the filesystem repository truncating write path.

## Fix Requirement

Register `tmpfile_cleanup` only after `dav_fs_mktemp()` succeeds and the temp file is actually created by this stream.

## Patch Rationale

The patch moves cleanup registration behind `rv == APR_SUCCESS`. This preserves normal successful truncating-write behavior, including cleanup of an owned temp file on abort and cleanup cancellation after commit. On failed temp creation, no cleanup is registered, so the request pool cannot later delete an unowned path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/dav/fs/repos.c b/modules/dav/fs/repos.c
index 64bc894..8f59d8b 100644
--- a/modules/dav/fs/repos.c
+++ b/modules/dav/fs/repos.c
@@ -936,8 +936,10 @@ static dav_error * dav_fs_open_stream(const dav_resource *resource,
         ds->temppath = apr_pstrcat(p, ap_make_dirstr_parent(p, ds->pathname),
                                    DAV_FS_TMP_PREFIX "XXXXXX", NULL);
         rv = dav_fs_mktemp(&ds->f, ds->temppath, ds->p);
-        apr_pool_cleanup_register(p, ds, tmpfile_cleanup,
-                                  apr_pool_cleanup_null);
+        if (rv == APR_SUCCESS) {
+            apr_pool_cleanup_register(p, ds, tmpfile_cleanup,
+                                      apr_pool_cleanup_null);
+        }
     }
     else if (mode == DAV_MODE_WRITE_SEEKABLE) {
         rv = apr_file_open(&ds->f, ds->pathname, flags | APR_FOPEN_EXCL,
```