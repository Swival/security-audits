# Truncated Vary Entry Reads Expire

## Classification

Memory safety, medium severity, out-of-bounds/uninitialized read.

Confidence: certain.

## Affected Locations

`modules/cache/mod_cache_socache.c:542`

## Summary

`open_entity()` reads an `apr_time_t expire` field from a retrieved socache Vary entry without first proving that the retrieved entry contains enough bytes for that field. A truncated Vary-format cache entry can therefore make `memcpy()` read past the valid returned object length.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced and patched.

## Preconditions

- `socache_provider->retrieve()` returns success for a cache lookup.
- The returned object length is at least `sizeof(apr_uint32_t)` so the initial `format` read succeeds.
- The retrieved `format` equals `CACHE_SOCACHE_VARY_FORMAT_VERSION`.
- The returned `buffer_len` is less than `sizeof(format) + sizeof(apr_time_t)`.

## Proof

`retrieve()` populates `sobj->buffer` and writes the actual returned length into local `buffer_len`.

The code rejects only entries where:

```c
if (buffer_len >= sobj->buffer_len)
```

It does not reject entries that are too short for the Vary header fields.

After reading the format, the code sets:

```c
slider = sizeof(format);
```

Then, for Vary-format entries, it immediately executes:

```c
memcpy(&expire, sobj->buffer + slider, sizeof(expire));
```

When `buffer_len < sizeof(format) + sizeof(expire)`, this copies bytes beyond the retrieved cache entry. The reproducer confirmed this is reachable for a truncated Vary entry and occurs before later parsing detects EOF.

## Why This Is A Real Bug

The socache buffer allocation size is not the same as the retrieved object length. `sobj->buffer` may be large enough as allocated storage, but only `buffer_len` bytes are valid data returned by the provider.

Reading `expire` without validating `buffer_len` violates the parser’s bounds invariant and can copy stale or uninitialized bytes from the APR-allocated buffer. The copied `expire` value is not subsequently used, limiting practical impact, but the out-of-bounds/uninitialized read still occurs on a cache lookup that hits a malformed or truncated Vary entry.

## Fix Requirement

Before copying `expire`, require that the retrieved Vary entry contains at least:

```c
sizeof(format) + sizeof(expire)
```

If not, treat the cache entry as invalid and remove/fail it instead of continuing.

## Patch Rationale

The patch checks the remaining valid bytes before the `memcpy()`:

```c
if (buffer_len - slider < sizeof(expire)) {
```

At this point `slider == sizeof(format)`, so the check proves that the retrieved object contains the full `expire` field. On failure, it logs the malformed cache entry, sets `nkey = key`, and jumps to the existing `fail` path so the invalid socache entry is removed consistently with other corrupt cache-entry handling.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/mod_cache_socache.c b/modules/cache/mod_cache_socache.c
index 38f1bfb..6567e1e 100644
--- a/modules/cache/mod_cache_socache.c
+++ b/modules/cache/mod_cache_socache.c
@@ -530,6 +530,12 @@ static int open_entity(cache_handle_t *h, request_rec *r, const char *key)
         apr_array_header_t* varray;
         apr_time_t expire;
 
+        if (buffer_len - slider < sizeof(expire)) {
+            ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r, APLOGNO(10426)
+                    "Cache vary entry for key '%s' too short, removing", key);
+            nkey = key;
+            goto fail;
+        }
         memcpy(&expire, sobj->buffer + slider, sizeof(expire));
         slider += sizeof(expire);
```