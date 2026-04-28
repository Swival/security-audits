# Signed Overflow In Power-Of-Two Rounding

## Classification

Invariant violation, medium severity. Confidence: certain.

## Affected Locations

- `modules/http2/h2_push.c:563`
- `modules/http2/h2_push.c:824`

## Summary

`ceil_power_of_2()` operates on signed `apr_int32_t` and returns `++n` after bit spreading. For inputs greater than `1073741824`, the bit-spread value becomes `INT_MAX`, and `++n` triggers signed integer overflow. This is undefined behavior and can corrupt diary size and digest log calculations.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Caller supplies `N > 1073741824` to `h2_push_diary_create()`.
- Or caller supplies `maxP > 1073741824` to `h2_push_diary_digest_get()`.

## Proof

`h2_push_diary_create()` reaches `diary_create()`, where `N` was only checked as positive before being passed to `ceil_power_of_2(N)`.

`h2_push_diary_digest_get(..., int maxP, ...)` used `ceil_power_of_2(maxP)` without a local upper bound.

For `n = 1073741825`, `ceil_power_of_2()` performs:

```c
--n;
n |= n >> 1;
n |= n >> 2;
n |= n >> 4;
n |= n >> 8;
n |= n >> 16;
return ++n;
```

The bit spreading produces `2147483647`, then `++n` overflows signed `apr_int32_t`. UBSan reports:

```text
runtime error: signed integer overflow: 2147483647 + 1 cannot be represented
1073741825 -> -2147483648
```

A practical direct-call impact exists: `h2_push_diary_create(..., 1073741825)` can create a diary with negative `NMax` and `N`. Later, `h2_push_diary_append()` evaluates `diary->entries->nelts >= diary->N`; with negative `N`, the condition is always true and can loop indefinitely.

## Why This Is A Real Bug

Signed integer overflow in C is undefined behavior, not a harmless wraparound. The overflowed result is used as a sizing invariant for `diary->NMax`, `diary->N`, and digest logarithm calculations. The resulting negative size can break diary eviction logic and cause non-terminating behavior.

The normal in-tree configuration path caps `H2PushDiarySize` in `modules/http2/h2_config.c:873`, reducing exposure for standard configuration-triggered `N` values. However, the affected functions are public or externally reachable within the module boundary, and `h2_push_diary_digest_get()` had no local upper bound for `maxP`.

## Fix Requirement

Reject values greater than `1073741824` before they reach `ceil_power_of_2()`, or rewrite the rounding helper to use checked unsigned widening before increment.

## Patch Rationale

The patch enforces the maximum safe signed input directly at both call sites that accept externally supplied bounds:

```diff
-    if (N > 0) {
+    if (N > 0 && N <= (1 << 30)) {
```

This prevents diary creation from passing an overflowing `N` into `ceil_power_of_2()`.

```diff
+    if (maxP > (1 << 30)) {
+        return APR_EINVAL;
+    }
     log2pmax = h2_log2(ceil_power_of_2(maxP));
```

This prevents digest generation from passing an overflowing `maxP` into `ceil_power_of_2()` and reports invalid input through the existing APR status mechanism.

The chosen bound is exact: `1073741824` is the largest input for which the next power of two still fits in signed 32-bit integer range.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/http2/h2_push.c b/modules/http2/h2_push.c
index e6a10c5..e9f5128 100644
--- a/modules/http2/h2_push.c
+++ b/modules/http2/h2_push.c
@@ -551,7 +551,7 @@ static h2_push_diary *diary_create(apr_pool_t *p, h2_push_digest_type dtype,
 {
     h2_push_diary *diary = NULL;
     
-    if (N > 0) {
+    if (N > 0 && N <= (1 << 30)) {
         diary = apr_pcalloc(p, sizeof(*diary));
         
         diary->NMax        = ceil_power_of_2(N);
@@ -821,6 +821,9 @@ apr_status_t h2_push_diary_digest_get(h2_push_diary *diary, apr_pool_t *pool,
      * log2p + log2n == mask_bits. We can use a lower log2p
      * and have a shorter set encoding...
      */
+    if (maxP > (1 << 30)) {
+        return APR_EINVAL;
+    }
     log2pmax = h2_log2(ceil_power_of_2(maxP));
     
     memset(&encoder, 0, sizeof(encoder));
```