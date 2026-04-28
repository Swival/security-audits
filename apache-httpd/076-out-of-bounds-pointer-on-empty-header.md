# Out-Of-Bounds Pointer On Empty Header

## Classification

Memory safety, low severity. Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_http.c:922`

## Summary

`ap_proxy_read_headers()` trims trailing whitespace from backend response header values by computing a pointer to the last byte of the value. For an empty value, this forms a pointer one byte before the start of the value buffer, which is undefined behavior in C even though the later loop condition prevents dereference.

## Provenance

Verified from the provided source, reproducer summary, and patch. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- A proxied backend sends a response header with an empty value.
- Example wire header: `X:\r\n`
- Whitespace-only values also reach the same trimming logic after leading whitespace is skipped.

## Proof

`ap_proxy_http_process_response()` reads the backend status line and calls `ap_proxy_read_headers()` for HTTP/1 response headers.

In `ap_proxy_read_headers()`:

```c
*value = '\0';
++value;

while (apr_isspace(*value))
    ++value;

for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
    *end = '\0';
```

For `X:\r\n`, `value` points to an empty string after the colon. Therefore `strlen(value) == 0`, and `&value[strlen(value)-1]` becomes `&value[-1]`.

The reproducer confirmed this with an equivalent UBSan-instrumented snippet, which reported:

```text
runtime error: addition of unsigned offset ... overflowed
```

Execution then continued with `value=''`.

## Why This Is A Real Bug

C only permits pointer arithmetic within the same array object or one element past it. Forming `value - 1` is outside those bounds and is undefined behavior before any loop condition can prevent dereference.

The header is backend-controlled, so a backend response can trigger the invalid pointer arithmetic during proxy response parsing before `process_proxy_header()` handles the header. Practical impact is low, but sanitized or hardened builds may abort, and normal builds rely on undefined behavior.

## Fix Requirement

Do not compute a pointer before `value`. Trailing whitespace trimming must start from a valid in-bounds position, including when the header value is empty.

## Patch Rationale

The patch changes the trim loop to start at `value + strlen(value)`, which is either the NUL terminator for non-empty values or exactly `value` for empty values. Both are valid positions. The loop then inspects `end[-1]` only after confirming `end > value`.

This preserves existing behavior for non-empty values while making the empty-value case safe.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_http.c b/modules/proxy/mod_proxy_http.c
index bd57b4d..74166d4 100644
--- a/modules/proxy/mod_proxy_http.c
+++ b/modules/proxy/mod_proxy_http.c
@@ -925,8 +925,8 @@ static apr_status_t ap_proxy_read_headers(request_rec *r, request_rec *rr,
             ++value;            /* Skip to start of value   */
 
         /* should strip trailing whitespace as well */
-        for (end = &value[strlen(value)-1]; end > value && apr_isspace(*end); --end)
-            *end = '\0';
+        for (end = value + strlen(value); end > value && apr_isspace(end[-1]); --end)
+            end[-1] = '\0';
 
         /* make sure we add so as not to destroy duplicated headers
          * Modify headers requiring canonicalisation and/or affected
```