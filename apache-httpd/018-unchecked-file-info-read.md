# Unchecked File Info Read

## Classification

Memory safety, medium severity.

Confidence: certain.

## Affected Locations

`modules/cache/mod_cache_disk.c:561`

## Summary

`open_entity()` reads `finfo.inode` and `finfo.device` after `apr_file_info_get()` even when that call fails. On failure, those `apr_finfo_t` fields are indeterminate stack data, so the cache body/header identity decision is made from uninitialized memory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A cached entity has a body, and `apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_IDENT, dobj->data.fd)` fails during cache lookup.

## Proof

Normal cache lookup reaches the disk provider through `cache_storage.c:248`, which calls `open_entity()`. If the cached header records `has_body`, `open_entity()` opens `dobj->data.fd` and calls:

```c
rc = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_IDENT,
        dobj->data.fd);
if (rc == APR_SUCCESS) {
    dobj->file_size = finfo.size;
}

if (dobj->disk_info.inode == finfo.inode &&
        dobj->disk_info.device == finfo.device) {
```

Only `dobj->file_size` is guarded by `rc == APR_SUCCESS`. The subsequent inode/device comparison executes regardless of `rc`, so `finfo.inode` and `finfo.device` are read when uninitialized.

The store path shows the intended contract: `modules/cache/mod_cache_disk.c:1226` treats `apr_file_info_get(... APR_FINFO_IDENT)` failure as fatal and returns before using `finfo`.

## Why This Is A Real Bug

`apr_finfo_t finfo` is a stack object. If `apr_file_info_get()` returns `APR_INCOMPLETE` or another non-success status, the requested identity fields are not guaranteed to be initialized. Reading them is undefined behavior.

Those indeterminate values directly control whether the cache entry is accepted or declined. If the comparison happens to pass, `h->cache_obj` is installed while `dobj->file_size` was not updated. Later, `recall_body()` uses `dobj->file_size` at `modules/cache/mod_cache_disk.c:906`, which can serve an incorrect or truncated cached body.

## Fix Requirement

Return `DECLINED` unless `apr_file_info_get()` succeeds before using any field from `finfo`.

## Patch Rationale

The patch converts the success-only size assignment into a fail-closed guard. If file metadata cannot be read, the header file is closed and the cache entry is declined before any `finfo` field is accessed.

This preserves the existing behavior for successful metadata reads while eliminating the uninitialized read and preventing cache acceptance without a valid file size.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_disk.c b/modules/cache/mod_cache_disk.c
index 8d17a19..9fd12b3 100644
--- a/modules/cache/mod_cache_disk.c
+++ b/modules/cache/mod_cache_disk.c
@@ -560,9 +560,11 @@ static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
 
         rc = apr_file_info_get(&finfo, APR_FINFO_SIZE | APR_FINFO_IDENT,
                 dobj->data.fd);
-        if (rc == APR_SUCCESS) {
-            dobj->file_size = finfo.size;
+        if (rc != APR_SUCCESS) {
+            apr_file_close(dobj->hdrs.fd);
+            return DECLINED;
         }
+        dobj->file_size = finfo.size;
 
         /* Atomic check - does the body file belong to the header file? */
         if (dobj->disk_info.inode == finfo.inode &&
```