# Signed Overflow In Freshness Calculation

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

`modules/cache/cache_util.c:722`

## Summary

`cache_check_freshness()` performed cache freshness arithmetic in signed `apr_int64_t`:

```c
age < (maxage + maxstale - minfresh)
```

A client-controlled huge `Cache-Control: max-stale=<value>` could make `maxage + maxstale` overflow when a cached object had a positive freshness lifetime. Signed integer overflow in C is undefined behavior, so the freshness decision could become compiler-, sanitizer-, or optimization-dependent.

## Provenance

Verified from the supplied reproduced finding and patch. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- A cached object exists.
- The cached response supplies a positive `max-age`.
- The cached response lacks `must-revalidate`, `proxy-revalidate`, and `s-maxage`, because those reset `maxstale` to zero.
- The client sends a huge `Cache-Control: max-stale` value accepted by `apr_strtoff()`.

## Proof

Request `Cache-Control` comes from `r->headers_in` and is parsed by `ap_cache_control()`.

For `max-stale=<number>`, `ap_cache_control()` accepts the value with `apr_strtoff()` and stores it in:

```c
cache->control_in.max_stale_value
```

`cache_check_freshness()` then assigns it to `maxstale` and evaluates:

```c
age < (maxage + maxstale - minfresh)
```

With `maxstale` near `INT64_MAX` and positive `maxage`, the signed addition overflows.

A minimal equivalent UBSan reproduction is:

```c
int64_t age = 1;
int64_t maxage = 60;
int64_t maxstale = INT64_MAX;
int64_t minfresh = 0;

if (age < (maxage + maxstale - minfresh)) {
    puts("fresh");
}
```

UBSan reports:

```text
runtime error: signed integer overflow: 60 + 9223372036854775807 cannot be represented in type 'int64_t'
```

## Why This Is A Real Bug

The overflowing operand is client-influenced through `Cache-Control: max-stale`.

The value is not rejected before the freshness comparison. Existing guards only neutralize `maxstale` when the cached response has `must-revalidate`, `proxy-revalidate`, or `s-maxage`; otherwise the untrusted value reaches the signed arithmetic.

Because signed overflow is undefined behavior in C, the cache freshness decision is not reliable. Practical outcomes include incorrect fresh/stale classification or sanitizer/compiler-dependent failure.

## Fix Requirement

Freshness comparisons must avoid signed overflow. Negative or overflowing directive values must be rejected, or the freshness calculation must use checked or saturation-safe arithmetic before comparison.

## Patch Rationale

The patch introduces `cache_freshness_lifetime_is_fresh()` and rewrites the freshness checks to avoid the vulnerable expression.

The helper:

- Rejects negative `age`, `maxstale`, and `minfresh`.
- Converts non-negative operands to `apr_uint64_t` before addition.
- Compares `age + minfresh` against `lifetime + maxstale`.
- Handles negative lifetimes separately without evaluating the previous overflowing expression.
- Changes `maxage != -1` to `maxage >= 0`, avoiding use of unexpected negative values as valid lifetimes.

This preserves the intended freshness comparison while removing signed `apr_int64_t` overflow from the client-influenced path.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/cache_util.c b/modules/cache/cache_util.c
index fc36431..d787f6f 100644
--- a/modules/cache/cache_util.c
+++ b/modules/cache/cache_util.c
@@ -530,6 +530,26 @@ int ap_cache_check_no_store(cache_request_rec *cache, request_rec *r)
     return 1;
 }
 
+static int cache_freshness_lifetime_is_fresh(apr_int64_t age,
+        apr_int64_t lifetime, apr_int64_t maxstale, apr_int64_t minfresh)
+{
+    apr_uint64_t adjusted_age;
+
+    if (age < 0 || maxstale < 0 || minfresh < 0) {
+        return 0;
+    }
+
+    adjusted_age = (apr_uint64_t)age + (apr_uint64_t)minfresh;
+    if (lifetime < 0) {
+        apr_int64_t adjusted_lifetime = lifetime + maxstale;
+
+        return adjusted_lifetime > 0
+            && adjusted_age < (apr_uint64_t)adjusted_lifetime;
+    }
+
+    return adjusted_age < (apr_uint64_t)lifetime + (apr_uint64_t)maxstale;
+}
+
 int cache_check_freshness(cache_handle_t *h, cache_request_rec *cache,
         request_rec *r)
 {
@@ -693,10 +713,14 @@ int cache_check_freshness(cache_handle_t *h, cache_request_rec *cache,
     }
 
     /* handle expiration */
-    if (((maxage != -1) && (age < (maxage + maxstale - minfresh))) ||
+    if (((maxage >= 0)
+         && cache_freshness_lifetime_is_fresh(age, maxage, maxstale,
+                                              minfresh)) ||
         ((smaxage == -1) && (maxage == -1) &&
          (info->expire != APR_DATE_BAD) &&
-         (age < (apr_time_sec(info->expire - info->date) + maxstale - minfresh)))) {
+         cache_freshness_lifetime_is_fresh(age,
+                                           apr_time_sec(info->expire - info->date),
+                                           maxstale, minfresh))) {
 
         warn_head = apr_table_get(h->resp_hdrs, "Warning");
```