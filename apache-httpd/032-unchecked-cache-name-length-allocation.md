# Unchecked Cache Name Length Allocation

## Classification

Memory safety, medium severity.

## Affected Locations

`support/htcacheclean.c:458`

## Summary

`htcacheclean` listing mode trusts the on-disk `disk_info.name_len` field from cache header files. A crafted `.header` file can set `name_len` to `APR_SIZE_MAX`, causing `len + 1` to wrap during allocation and the subsequent `url[len] = 0` write to go out of bounds.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

An attacker can place a crafted cache header file under the scanned cache path.

## Proof

The issue is reachable through cache URL listing:

- `htcacheclean -a -p <cachepath>` or `htcacheclean -A -p <cachepath>` sets `listurls`.
- `main()` calls `list_urls(path, pool, round)` before any purge path.
- `list_urls()` recursively scans regular files whose names contain `.header`.
- For `format == DISK_FORMAT_VERSION`, it seeks to offset 0 and reads attacker-controlled bytes into `disk_cache_info_t disk_info`.
- `disk_info.name_len` is assigned directly to `apr_size_t len`.
- `apr_palloc(p, len + 1)` can wrap when `name_len == APR_SIZE_MAX`.
- `url[len] = 0` then writes out of bounds before any validation that the length fits in the file or allocation size.

The write occurs before the `listextended` branch, so both `-a` and `-A` are affected.

## Why This Is A Real Bug

The cache header file is treated as trusted metadata even though it is read from disk under the scanned cache tree. The value of `disk_info.name_len` controls both allocation size and a later indexed write. Because unsigned addition wraps, `len + 1` can allocate too small a buffer, including zero bytes, while `url[len] = 0` still writes at the attacker-controlled offset.

This is memory corruption and can crash `htcacheclean` in listing mode.

## Fix Requirement

Reject `disk_info.name_len` values greater than `APR_SIZE_MAX - 1` before computing `len + 1`.

## Patch Rationale

The patch adds an explicit overflow guard immediately after loading `disk_info.name_len` and before allocation:

```c
if (len > APR_SIZE_MAX - 1) {
    apr_file_close(fd);
    continue;
}
```

This prevents `len + 1` from wrapping and skips malformed cache header files without attempting to allocate or write through the derived pointer.

## Residual Risk

None

## Patch

```diff
diff --git a/support/htcacheclean.c b/support/htcacheclean.c
index 57c5c5b..5876ef7 100644
--- a/support/htcacheclean.c
+++ b/support/htcacheclean.c
@@ -457,6 +457,10 @@ static int list_urls(char *path, apr_pool_t *pool, apr_off_t round)
                             if (apr_file_read_full(fd, &disk_info, len, &len)
                                     == APR_SUCCESS) {
                                 len = disk_info.name_len;
+                                if (len > APR_SIZE_MAX - 1) {
+                                    apr_file_close(fd);
+                                    continue;
+                                }
                                 url = apr_palloc(p, len + 1);
                                 url[len] = 0;
```