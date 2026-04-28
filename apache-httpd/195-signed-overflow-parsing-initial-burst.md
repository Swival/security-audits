# signed overflow parsing initial burst

## Classification

Validation gap, low severity. Confidence: certain.

## Affected Locations

`modules/filters/mod_ratelimit.c:99`

## Summary

`rate-initial-burst` is parsed with `atoi()` and immediately multiplied by `1024` in signed `int` arithmetic. A value of `2097152` produces `2147483648`, which exceeds `INT_MAX` on normal 32-bit-`int` ABIs and triggers C signed integer overflow before the existing `burst <= 0` guard can execute.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The issue was reproduced with a minimal UBSan harness for the exact expression, which reported:

```text
runtime error: signed integer overflow: 2097152 * 1024 cannot be represented in type 'int'
```

## Preconditions

- `rate-limit` is present and positive.
- `rate-initial-burst` is present.
- `rate-initial-burst` is `2097152` or larger.
- The first `rate_limit_filter()` setup path is reached for a main request.

## Proof

The vulnerable path is:

```c
rl = apr_table_get(f->r->subprocess_env, "rate-initial-burst");
if (rl != NULL) {
    burst = atoi(rl) * 1024;
    if (burst <= 0) {
        ...
        burst = 0;
    }
}
```

`atoi(rl)` returns `int`, and `1024` is also an `int` constant, so the multiplication is performed as signed `int` arithmetic.

For `rate-initial-burst=2097152`:

```text
2097152 * 1024 = 2147483648
```

`2147483648` is greater than `INT_MAX` on common 32-bit-`int` platforms, so the multiplication itself has undefined behavior. The subsequent `burst <= 0` check cannot reliably mitigate the issue because the overflow has already occurred.

## Why This Is A Real Bug

The input is reachable from `f->r->subprocess_env` during rate limit filter initialization. The code attempts to reject invalid or excessive burst values only after multiplying them, but C signed overflow is undefined behavior at the multiplication site. This makes the validation order incorrect and source-supported.

## Fix Requirement

Parse `rate-initial-burst` into a wider integer type and validate the kilobyte value before multiplying by `1024`. Reject non-positive values and values larger than the maximum representable `int` byte count divided by `1024`.

## Patch Rationale

The patch replaces the overflowing expression with:

```c
apr_int64_t burst_kb = apr_atoi64(rl);

if (burst_kb <= 0 || burst_kb > APR_INT32_MAX / 1024) {
    ...
    burst = 0;
}
else {
    burst = (int)(burst_kb * 1024);
}
```

This makes the parse and bounds check occur in `apr_int64_t`, avoiding signed `int` overflow. The multiplication is performed only after proving the result fits within a signed 32-bit integer, matching the existing `int burst` storage type.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_ratelimit.c b/modules/filters/mod_ratelimit.c
index d16eb39..1d37aea 100644
--- a/modules/filters/mod_ratelimit.c
+++ b/modules/filters/mod_ratelimit.c
@@ -96,12 +96,16 @@ rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *bb)
         /* Configuration: optional initial burst */
         rl = apr_table_get(f->r->subprocess_env, "rate-initial-burst");
         if (rl != NULL) {
-            burst = atoi(rl) * 1024;
-            if (burst <= 0) {
+            apr_int64_t burst_kb = apr_atoi64(rl);
+
+            if (burst_kb <= 0 || burst_kb > APR_INT32_MAX / 1024) {
                ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                              APLOGNO(03489) "rl: disabling burst: rate-initial-burst = %s (too high?)", rl);
                burst = 0;
             }
+            else {
+                burst = (int)(burst_kb * 1024);
+            }
         }
 
         /* Set up our context */
```