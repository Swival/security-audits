# Short Cache Entry Reads Missing Format

## Classification

Memory safety, medium severity.

Confidence: certain.

## Affected Locations

`modules/cache/mod_cache_socache.c:535`

## Summary

`open_entity()` reads the cache-entry format field with `memcpy(&format, sobj->buffer, sizeof(format))` immediately after a successful socache retrieval. The existing size check only rejects entries whose returned length is at least the local buffer size. It does not reject entries shorter than `sizeof(apr_uint32_t)`, so a 0-3 byte cache value causes bytes past the retrieved entry to be read from the allocated buffer and used for control flow.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

The issue was reproduced and patched from the supplied evidence.

## Preconditions

- `socache_provider->retrieve()` returns `APR_SUCCESS`.
- The returned `buffer_len` is fewer than four bytes.
- A cache lookup reaches `open_entity()` for the affected key.
- This is practical with external socache backends such as memcache or Redis, which accept and copy values with length `0-3` and return success.

## Proof

`open_entity()` allocates `sobj->buffer`, sets `buffer_len = sobj->buffer_len`, and passes both to `socache_provider->retrieve()`.

After retrieval succeeds, the code only checks:

```c
if (buffer_len >= sobj->buffer_len) {
    ...
    return DECLINED;
}
```

It then immediately executes:

```c
memcpy(&format, sobj->buffer, sizeof(format));
slider = sizeof(format);
```

When `buffer_len < sizeof(apr_uint32_t)`, this copies bytes beyond the retrieved cache value. Those bytes are uninitialized pool-buffer contents. The resulting `format` value is then used to select the vary-entry path, invalid-version removal path, or normal disk-format parsing path.

The reproducer confirmed that memcache and Redis socache providers can return success for short values, making a short value under the generated cache key sufficient to trigger the path during lookup.

## Why This Is A Real Bug

The code treats successful retrieval as proof that the first four bytes are available, but the socache API returns the actual retrieved length through `buffer_len`. A successful retrieval with `buffer_len` in `0..3` does not provide enough bytes for `apr_uint32_t format`.

The subsequent branch on `format` is a control-flow decision based on indeterminate data. That is a concrete uninitialized read, not just defensive hardening.

## Fix Requirement

Before the first `memcpy()` into `format`, reject retrieved entries where:

```c
buffer_len < sizeof(format)
```

The rejection must happen after `retrieve()` succeeds and before any read from `sobj->buffer` as an `apr_uint32_t`.

## Patch Rationale

The patch adds a length check immediately after the existing oversized-entry check and before the format read. Short entries are logged, the temporary pool is destroyed, and lookup returns `DECLINED`.

This directly enforces the minimum serialized-entry size needed by the next operation and prevents uninitialized bytes from influencing parsing or removal behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_socache.c b/modules/cache/mod_cache_socache.c
index 38f1bfb..e13a836 100644
--- a/modules/cache/mod_cache_socache.c
+++ b/modules/cache/mod_cache_socache.c
@@ -521,6 +521,13 @@ static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
         sobj->pool = NULL;
         return DECLINED;
     }
+    if (buffer_len < sizeof(format)) {
+        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, rc, r, APLOGNO(02353)
+                "Key found in cache but too short, ignoring: %s", key);
+        apr_pool_destroy(sobj->pool);
+        sobj->pool = NULL;
+        return DECLINED;
+    }
 
     /* read the format from the cache file */
     memcpy(&format, sobj->buffer, sizeof(format));
```