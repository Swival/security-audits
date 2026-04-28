# Invalid Pointer For Empty Header Value

## Classification

Memory safety, medium severity. Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_hcheck.c:771`

## Summary

`hc_read_headers()` trims response header values during proxy health checks. For a backend header with an empty value, such as `X:`, the value pointer refers to an empty string. The code computes `&value[strlen(value)-1]`, which underflows when `strlen(value)` is `0` and forms an invalid pointer before the value buffer.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- HTTP health checks are configured for a backend.
- The health-check backend returns a response containing a header line with an empty value, for example `X:`.

## Proof

- `hc_check_http()` sends the health-check request with `hc_send()` and then calls `hc_read_headers()` before status evaluation.
- `hc_read_headers()` accepts the HTTP status line, then reads response headers in a loop.
- A header line `X:` passes the colon check because `strchr(buffer, ':')` succeeds.
- After `*value = '\0'; ++value;`, `value` points at the terminating NUL for the empty value.
- Whitespace skipping leaves `value` unchanged.
- `strlen(value)` is `0`, so `strlen(value)-1` underflows to `SIZE_MAX`.
- The expression `&value[strlen(value)-1]` forms `value - 1`, causing invalid pointer arithmetic.
- An extracted equivalent snippet compiled with `-fsanitize=undefined,address` reports a runtime pointer arithmetic overflow.

## Why This Is A Real Bug

The invalid pointer is formed before the loop condition can reject it. C pointer arithmetic outside the object bounds is undefined behavior even if the resulting pointer is not dereferenced. A backend participating in configured HTTP health checks can trigger this path with a syntactically accepted empty header value. Normal builds may appear unaffected, but sanitizer, hardened, or optimized builds can trap or miscompile around the undefined behavior.

## Fix Requirement

Handle an empty header value before subtracting one from `strlen(value)`.

## Patch Rationale

The patch checks `if (*value)` before computing the trailing-character pointer. Non-empty values retain the existing trailing-whitespace trimming behavior. Empty values are added unchanged as empty strings, avoiding the underflow and invalid pointer formation.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_hcheck.c b/modules/proxy/mod_proxy_hcheck.c
index 70f1de8..b09a39c 100644
--- a/modules/proxy/mod_proxy_hcheck.c
+++ b/modules/proxy/mod_proxy_hcheck.c
@@ -779,8 +779,10 @@ static int hc_read_headers(request_rec *r)
         ++value;
         while (apr_isspace(*value))
             ++value;            /* Skip to start of value   */
-        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
-            *end = '\0';
+        if (*value) {
+            for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
+                *end = '\0';
+        }
         apr_table_add(r->headers_out, buffer, value);
     }
```