# Empty Response Header Underflows Pointer

## Classification

Memory safety, undefined behavior. Severity: medium. Confidence: certain.

## Affected Locations

`modules/proxy/mod_proxy_uwsgi.c:385`

## Summary

`mod_proxy_uwsgi` trims backend response header values by computing the last character pointer as `&value[strlen(value) - 1]`. If a uwsgi backend returns a header with an empty value, `strlen(value)` is `0`, so the subtraction underflows and forms an invalid pointer before any loop guard can prevent it.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- `mod_proxy_uwsgi` is proxying to a uwsgi backend.
- The backend returns a response header line containing `:` with no value after optional whitespace, for example `X-Test:`.
- The response header parser reaches the trimming logic in `uwsgi_response`.

## Proof

The backend response header parsing loop reads each header line with `ap_getline` in `uwsgi_response`.

Relevant flow:

```c
value = strchr(buffer, ':');
*value++ = '\0';

while (apr_isspace(*value))
    ++value;

for (end = &value[strlen(value) - 1];
     end > value && apr_isspace(*end); --end)
    *end = '\0';
```

For an empty header value:

- `strchr(buffer, ':')` finds the separator.
- `*value++ = '\0'` terminates the header name and advances `value`.
- `value` points to `'\0'`, or whitespace skipping advances it to `'\0'`.
- `strlen(value)` returns `0`.
- `strlen(value) - 1` underflows as an unsigned `size_t`.
- `&value[strlen(value) - 1]` forms an invalid pointer expression.

Runtime reproduction with a minimal equivalent snippet under UBSan aborts with an unsigned offset overflow diagnostic on the same expression shape.

## Why This Is A Real Bug

The invalid pointer is computed before the loop condition can check `end > value`. In C, forming a pointer before the start of the object is undefined behavior, even if the pointer is not later dereferenced.

The input is backend-controlled and reachable during normal parsing of every uwsgi backend response header. Unsanitized builds may appear to continue, but sanitizer or hardened builds can abort, and the behavior is not valid under the C abstract machine.

## Fix Requirement

Handle empty values before subtracting from `strlen(value)`, or compute `end` only when `strlen(value) > 0`.

## Patch Rationale

The patch gates the trailing-whitespace trimming loop behind `if (*value)`. This preserves existing behavior for non-empty values while avoiding the invalid `strlen(value) - 1` computation for empty values.

Empty values are then passed to `ap_scan_http_field_content(value)`, which can validate the empty string without requiring pointer arithmetic before the buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/proxy/mod_proxy_uwsgi.c b/modules/proxy/mod_proxy_uwsgi.c
index 4e57196..1da2a73 100644
--- a/modules/proxy/mod_proxy_uwsgi.c
+++ b/modules/proxy/mod_proxy_uwsgi.c
@@ -386,9 +386,11 @@ static int uwsgi_response(request_rec *r, proxy_conn_rec * backend,
         }
         while (apr_isspace(*value))
             ++value;
-        for (end = &value[strlen(value) - 1];
-             end > value && apr_isspace(*end); --end)
-            *end = '\0';
+        if (*value) {
+            for (end = &value[strlen(value) - 1];
+                 end > value && apr_isspace(*end); --end)
+                *end = '\0';
+        }
         if (*ap_scan_http_field_content(value)) {
             /* invalid value */
             len = -1;
```