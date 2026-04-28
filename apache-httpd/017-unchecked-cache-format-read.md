# Unchecked Cache Format Read

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/cache/mod_cache_disk.c:457`

## Summary

`open_entity()` reads the cache header format field from an existing disk-cache header file but does not validate that `apr_file_read_full()` succeeded before using the stack local `format`. A truncated header file containing fewer than `sizeof(format)` bytes can leave `format` uninitialized or partially initialized, causing nondeterministic Vary/Disk/mismatch handling.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Disk cache is enabled and `open_entity()` is reached during a cache lookup.
- The cache header file exists.
- The cache header file contains fewer than `sizeof(format)` bytes.

## Proof

In `open_entity()`, `format` is declared as a stack local:

```c
apr_uint32_t format;
```

The function opens `dobj->vary.file`, then reads the format field:

```c
len = sizeof(format);
apr_file_read_full(dobj->vary.fd, &format, len, &len);
```

The return value is ignored. APR documents that `apr_file_read_full()` can return an error when fewer than the requested bytes are read, and the byte count must be checked before trusting the destination buffer.

Immediately afterward, `format` drives cache format classification:

```c
if (format == VARY_FORMAT_VERSION) {
    ...
}
else if (format != DISK_FORMAT_VERSION) {
    ...
}
else {
    ...
}
```

When the header is truncated, `format` may contain indeterminate stack data, so the branch selection is undefined and nondeterministic.

## Why This Is A Real Bug

The vulnerable path is reachable during normal disk-cache lookup whenever an existing header file is opened. A malformed, corrupted, or truncated header file is enough to trigger the short read.

The module already treats short reads as invalid cache entries elsewhere: `file_cache_recall_mydata()` checks the return value from `apr_file_read_full()` before using data read from the cache header. The unchecked read in `open_entity()` violates that local safety pattern and uses untrusted cache-file contents without validating that the required bytes were actually present.

## Fix Requirement

Check both:

- `apr_file_read_full()` return status.
- The resulting byte count equals `sizeof(format)`.

If either check fails, close the opened cache file and reject the cache entry before `format` is used.

## Patch Rationale

The patch stores the result of `apr_file_read_full()` in `rc`, verifies success and complete length, closes `dobj->vary.fd` on failure, and returns `DECLINED`.

This preserves existing cache-miss behavior for invalid cache entries while preventing use of uninitialized or partially initialized `format`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_disk.c b/modules/cache/mod_cache_disk.c
index 8d17a19..352aa24 100644
--- a/modules/cache/mod_cache_disk.c
+++ b/modules/cache/mod_cache_disk.c
@@ -454,7 +454,11 @@ static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
 
     /* read the format from the cache file */
     len = sizeof(format);
-    apr_file_read_full(dobj->vary.fd, &format, len, &len);
+    rc = apr_file_read_full(dobj->vary.fd, &format, len, &len);
+    if (rc != APR_SUCCESS || len != sizeof(format)) {
+        apr_file_close(dobj->vary.fd);
+        return DECLINED;
+    }
 
     if (format == VARY_FORMAT_VERSION) {
         apr_array_header_t* varray;
```