# htaccess Cache Omits override_list

## Classification

Authorization flaw, medium severity.

## Affected Locations

`server/config.c:1987`

## Summary

`ap_parse_htaccess()` accepted a caller-controlled `override_list` and used it to authorize directives through `parms.override_list`, but the per-request `.htaccess` cache key only considered `override` and directory path. A cached parse created under one `AllowOverrideList` could therefore be reused for the same directory under a different list, bypassing the intended directive authorization for the later context.

## Provenance

Verified from supplied source, reproducer analysis, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The same request parses the same filesystem directory with different `override_list` tables.

## Proof

`ap_parse_htaccess()` receives `override_list` and stores it in `parms.override_list`. `invoke_cmd()` then uses `parms.override_list` to decide whether a directive is permitted even when the normal `override` mask would reject it.

Before parsing any `.htaccess` file, `ap_parse_htaccess()` searches `r->htaccess` and returns a cached result when only these fields match:

- `cache->override == override`
- `strcmp(cache->dir, d) == 0`

The cache entry stores `dir`, `override`, `override_opts`, and `htaccess`, but stores no `override_list` identity or content. As a result, a later parse of the same directory with a different `override_list` can receive a cached `htaccess` config produced under the earlier directive permissions.

The reproducer confirmed practical reachability: `ap_directory_walk()` propagates `core_dir_config.override_list` into `opts.override_list`, passes it to `ap_parse_htaccess()`, and subrequests/internal redirects can inherit the parent request’s htaccess cache. Two URI mappings in one request can therefore reach the same directory with different merged `AllowOverrideList` tables.

## Why This Is A Real Bug

`AllowOverrideList` is an authorization boundary for which `.htaccess` directives may execute in a directory context. Reusing a cached `.htaccess` result across different `override_list` values means directive authorization is not evaluated for the effective context. If the first parse allows a directive and the second context should reject or ignore it, the second context can still receive the already-applied configuration.

## Fix Requirement

The `.htaccess` cache must not be reused across differing `override_list` values. A valid fix must either include `override_list` identity/content in the cache key or avoid caching when `override_list` is present.

## Patch Rationale

The patch disables both lookup and insertion in the `.htaccess` cache whenever `override_list != NULL`.

This is sufficient because `override_list` is the missing authorization input. When no list is present, the existing cache behavior remains unchanged. When a list is present, parsing is performed under the active list every time, so directive permissions cannot be inherited from a prior parse that used different `AllowOverrideList` state.

## Residual Risk

None

## Patch

```diff
diff --git a/server/config.c b/server/config.c
index 635b65d..c6663ab 100644
--- a/server/config.c
+++ b/server/config.c
@@ -2006,10 +2006,12 @@ AP_CORE_DECLARE(int) ap_parse_htaccess(ap_conf_vector_t **result,
     apr_status_t status;
 
     /* firstly, search cache */
-    for (cache = r->htaccess; cache != NULL; cache = cache->next) {
-        if (cache->override == override && strcmp(cache->dir, d) == 0) {
-            *result = cache->htaccess;
-            return OK;
+    if (override_list == NULL) {
+        for (cache = r->htaccess; cache != NULL; cache = cache->next) {
+            if (cache->override == override && strcmp(cache->dir, d) == 0) {
+                *result = cache->htaccess;
+                return OK;
+            }
         }
     }
 
@@ -2066,16 +2068,18 @@ AP_CORE_DECLARE(int) ap_parse_htaccess(ap_conf_vector_t **result,
         }
     }
 
-    /* cache it */
-    new = apr_palloc(r->pool, sizeof(struct htaccess_result));
-    new->dir = parms.path;
-    new->override = override;
-    new->override_opts = override_opts;
-    new->htaccess = dc;
+    if (override_list == NULL) {
+        /* cache it */
+        new = apr_palloc(r->pool, sizeof(struct htaccess_result));
+        new->dir = parms.path;
+        new->override = override;
+        new->override_opts = override_opts;
+        new->htaccess = dc;
 
-    /* add to head of list */
-    new->next = r->htaccess;
-    r->htaccess = new;
+        /* add to head of list */
+        new->next = r->htaccess;
+        r->htaccess = new;
+    }
 
     return OK;
 }
```