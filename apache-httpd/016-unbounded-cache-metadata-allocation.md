# Unbounded Cache Metadata Allocation

## Classification

Medium severity vulnerability.

## Affected Locations

`modules/cache/mod_cache_disk.c:243`

## Summary

`mod_cache_disk` trusted the on-disk `disk_cache_info_t.name_len` field before validating it. During cache lookup, a crafted or corrupt `.header` file could set `name_len` to an oversized value, causing `file_cache_recall_mydata()` to allocate `name_len + 1` bytes from the request pool before checking whether the cached URL matches the requested key.

This can exhaust worker memory or trigger allocator failure during normal cache lookup.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Disk cache is enabled.
- A cache `.header` file for the requested key exists.
- The header file contains an oversized `name_len` field.

## Proof

`open_entity()` opens the expected cache header file and calls `file_cache_recall_mydata()` during cache lookup.

In `file_cache_recall_mydata()`:

- `disk_cache_info_t` is read directly from disk into `dobj->disk_info`.
- `dobj->disk_info.name_len` is used in `apr_palloc(r->pool, dobj->disk_info.name_len + 1)`.
- No upper bound or addition-overflow check occurs before allocation.
- The URL comparison with `dobj->name` happens only after allocation and file read.

Therefore, a corrupt or crafted header with an oversized `name_len` can force an oversized request-pool allocation before the cache entry is rejected.

## Why This Is A Real Bug

`name_len` is attacker-influenced through the on-disk cache header and is treated as trusted metadata. The allocation occurs before semantic validation against the expected cache key.

Because the allocation is made from `r->pool`, the impact is per-request but still security-relevant: repeated or single large allocation attempts can exhaust memory, abort a worker, or crash depending on APR and allocator behavior.

The reproducer confirmed the vulnerable path is reachable by placing or corrupting the expected cache `.header` file for a requested key.

## Fix Requirement

Reject invalid `name_len` before allocation.

The fix must ensure:

- `name_len + 1` cannot overflow.
- `name_len` is bounded to the expected URL/key length.
- Mismatched metadata is rejected before `apr_palloc()`.

## Patch Rationale

The patch validates `dobj->disk_info.name_len` immediately after reading disk metadata and before allocation.

It rejects the entry when:

- `name_len == (apr_size_t)-1`, preventing `name_len + 1` wraparound.
- `name_len != strlen(dobj->name)`, ensuring the on-disk name length matches the expected cache key length before allocating.

This keeps valid cache entries working while preventing oversized metadata from controlling allocation size.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_disk.c b/modules/cache/mod_cache_disk.c
index 8d17a19..43ce22e 100644
--- a/modules/cache/mod_cache_disk.c
+++ b/modules/cache/mod_cache_disk.c
@@ -238,6 +238,11 @@ static int file_cache_recall_mydata(apr_file_t *fd, cache_info *info,
 
     memcpy(&info->control, &dobj->disk_info.control, sizeof(cache_control_t));
 
+    if (dobj->disk_info.name_len == (apr_size_t)-1 ||
+            dobj->disk_info.name_len != strlen(dobj->name)) {
+        return APR_EGENERAL;
+    }
+
     /* Note that we could optimize this by conditionally doing the palloc
      * depending upon the size. */
     urlbuff = apr_palloc(r->pool, dobj->disk_info.name_len + 1);
```