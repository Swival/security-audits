# Signed Overflow Parsing Rate Limit

## Classification

Medium severity validation gap.

Confidence: certain.

## Affected Locations

`modules/filters/mod_ratelimit.c:89`

## Summary

`mod_ratelimit` parsed the `rate-limit` request environment value with `atoi()` and immediately multiplied the resulting signed `int` by `1024`. A value of `2097152` is accepted by `atoi()`, but `2097152 * 1024` exceeds 32-bit `INT_MAX`, causing signed integer overflow before the existing `ratelimit <= 0` validation can run.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- The request is not a subrequest.
- The request environment contains `rate-limit`.
- `rate-limit` is set to `2097152` or larger.
- The rate limit filter reaches first-use context initialization.

## Proof

The vulnerable path is reached during first filter use when `ctx == NULL`.

Original code:

```c
rl = apr_table_get(f->r->subprocess_env, "rate-limit");

if (rl == NULL) {
    ap_remove_output_filter(f);
    return ap_pass_brigade(f->next, bb);
}

/* rl is in kilo bytes / second  */
ratelimit = atoi(rl) * 1024;
if (ratelimit <= 0) {
    ...
}
```

For `rate-limit=2097152`:

- `atoi("2097152")` returns `2097152`, which is representable as signed `int`.
- `2097152 * 1024` equals `2147483648`.
- `2147483648` exceeds 32-bit `INT_MAX`.
- The signed overflow occurs before `ratelimit <= 0` can reject the value.

The reproducer confirmed the equivalent expression under UBSan aborts with:

```text
runtime error: signed integer overflow: 2097152 * 1024 cannot be represented in type 'int'
```

## Why This Is A Real Bug

C signed integer overflow is undefined behavior. The existing validation is ineffective because it occurs after the overflowing multiplication.

Practical effects include:

- UBSan or hardened builds can abort on first filter use.
- Non-instrumented builds can wrap or otherwise produce invalid values.
- The filter may be disabled or misconfigured based on undefined behavior rather than explicit validation.

## Fix Requirement

Parse `rate-limit` without overflowing signed `int` arithmetic and reject values that cannot be safely converted from kilobytes per second to bytes per second.

Required bound:

```c
rate-limit <= INT_MAX / 1024
```

## Patch Rationale

The patch changes parsing from `atoi()` to `apr_strtoi64()`, stores the parsed value in `apr_int64_t`, and validates the value before multiplying:

```c
ratelimit = apr_strtoi64(rl, NULL, 10);
if (ratelimit <= 0 || ratelimit > INT_MAX / 1024) {
    ...
}
```

Only after validation does the code convert to bytes per second:

```c
ctx->speed = (int)ratelimit * 1024;
```

This ensures the multiplication is performed only for values that fit within signed `int`.

The patch also includes `<limits.h>` so `INT_MAX` is available.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/mod_ratelimit.c b/modules/filters/mod_ratelimit.c
index d16eb39..cfc7ec3 100644
--- a/modules/filters/mod_ratelimit.c
+++ b/modules/filters/mod_ratelimit.c
@@ -14,6 +14,8 @@
  * limitations under the License.
  */
 
+#include <limits.h>
+
 #include "httpd.h"
 #include "http_config.h"
 #include "http_log.h"
@@ -66,7 +68,7 @@ rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *bb)
     /* Set up our rl_ctx_t on first use */
     if (ctx == NULL) {
         const char *rl = NULL;
-        int ratelimit;
+        apr_int64_t ratelimit;
         int burst = 0;
 
         /* no subrequests. */
@@ -84,8 +86,8 @@ rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *bb)
         }
         
         /* rl is in kilo bytes / second  */
-        ratelimit = atoi(rl) * 1024;
-        if (ratelimit <= 0) {
+        ratelimit = apr_strtoi64(rl, NULL, 10);
+        if (ratelimit <= 0 || ratelimit > INT_MAX / 1024) {
             /* remove ourselves */
             ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, f->r,
                           APLOGNO(03488) "rl: disabling: rate-limit = %s (too high?)", rl);
@@ -108,7 +110,7 @@ rate_limit_filter(ap_filter_t *f, apr_bucket_brigade *bb)
         ctx = apr_palloc(f->r->pool, sizeof(rl_ctx_t));
         f->ctx = ctx;
         ctx->state = RATE_LIMIT;
-        ctx->speed = ratelimit;
+        ctx->speed = (int)ratelimit * 1024;
         ctx->burst = burst;
         ctx->do_sleep = 0;
```