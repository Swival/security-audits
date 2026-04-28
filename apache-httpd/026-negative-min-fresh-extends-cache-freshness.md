# Negative min-fresh Extends Cache Freshness

## Classification

Validation gap, medium severity.

## Affected Locations

`modules/cache/cache_util.c:1083`

## Summary

`Cache-Control: min-fresh` values are parsed with `apr_strtoff()` but negative values are accepted. During freshness checks, `minfresh` is subtracted from the allowed freshness window, so a negative value increases the window and can cause stale cached responses to be treated as fresh.

## Provenance

Verified and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

A client sends a request containing `Cache-Control: min-fresh` with a negative integer, for example:

```http
Cache-Control: min-fresh=-60
```

## Proof

`ap_cache_control()` parses request `Cache-Control` directives. For `min-fresh`, it accepts any successfully parsed integer:

```c
cc->min_fresh = 1;
cc->min_fresh_value = offt;
```

The parsed value is later copied into the freshness calculation when request cache-control is honored:

```c
minfresh = cache->control_in.min_fresh_value;
```

Freshness is then evaluated as:

```c
age < (maxage + maxstale - minfresh)
```

Because `minfresh` is subtracted, a negative value increases the permitted age.

Concrete case:

- Cached response has `max-age=10`
- Current cached response age is `20`
- Without the malicious directive: `20 < 10` is false, so the object is stale
- With `Cache-Control: min-fresh=-60`: `20 < 10 - (-60)` becomes `20 < 70`, so the stale object is treated as fresh

`cache_check_freshness()` is used by cache storage logic to decide whether to revalidate or serve from cache. If the expression evaluates true, the cached response is served without revalidation.

## Why This Is A Real Bug

`min-fresh` represents the minimum remaining freshness a client requires. A negative minimum freshness has no valid cache semantics and should not make stale content more acceptable. Accepting negative values reverses the directive’s intended effect and lets a request header extend cache freshness beyond the origin response’s freshness lifetime.

## Fix Requirement

Reject negative `min-fresh` values during `Cache-Control` parsing.

## Patch Rationale

The patch adds `offt >= 0` to the existing parse validation for `min-fresh`. This preserves valid non-negative values and prevents negative integers from setting `cc->min_fresh` or `cc->min_fresh_value`.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/cache/cache_util.c b/modules/cache/cache_util.c
index fc36431..8218bac 100644
--- a/modules/cache/cache_util.c
+++ b/modules/cache/cache_util.c
@@ -1079,7 +1079,7 @@ int ap_cache_control(request_rec *r, cache_control_t *cc,
                 else if (!ap_cstr_casecmpn(token, "min-fresh", 9)) {
                     if (token[9] == '='
                             && !apr_strtoff(&offt, token + 10, &endp, 10)
-                            && endp > token + 10 && !*endp) {
+                            && endp > token + 10 && !*endp && offt >= 0) {
                         cc->min_fresh = 1;
                         cc->min_fresh_value = offt;
                     }
```