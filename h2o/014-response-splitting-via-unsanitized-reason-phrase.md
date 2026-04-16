# Response splitting via unsanitized reason phrase

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http1.c:711`
- `lib/http1.c:822`
- `lib/http1.c:1153`

## Summary
`req->res.reason` is serialized into HTTP/1 status lines without CR/LF sanitization. If an application sets the reason phrase from untrusted input, attacker-controlled `\r` or `\n` bytes break the status line and inject arbitrary headers or a second response.

## Provenance
- Verified reproduced finding from local analysis and reproducer output
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- The application sets `req->res.reason` from untrusted input

## Proof
`flatten_headers` and the HTTP/1 informational response path format the status line with `%s` using `req->res.reason` directly, with no filtering at `lib/http1.c:711`, `lib/http1.c:822`, and `lib/http1.c:1153`.

A practical payload such as `OK\r\nSet-Cookie: pwn=1` produces wire output equivalent to:
```text
HTTP/1.1 200 OK\r\n
Set-Cookie: pwn=1\r\n
Connection: keep-alive\r\n
...
```

This demonstrates attacker-controlled bytes escaping the reason phrase and being interpreted as headers. The same issue is reachable for informational responses through `h2o_send_informational` into the HTTP/1 sender path. HTTP/2 is not affected because it does not place `req->res.reason` on the wire.

## Why This Is A Real Bug
HTTP/1.x response parsing treats CRLF as a line terminator. Allowing untrusted CR or LF in the reason phrase gives an attacker direct control over subsequent header lines, enabling response splitting and header injection. The sink is real, reachable, and directly attacker-influenced under the stated precondition.

## Fix Requirement
Reject or strip `\r` and `\n` from `req->res.reason` before any HTTP/1 status-line formatting path emits it.

## Patch Rationale
The patch in `014-response-splitting-via-unsanitized-reason-phrase.patch` sanitizes the reason phrase before HTTP/1 serialization so CR/LF cannot reach the wire. This preserves normal reason text while removing the only characters that can terminate the status line and create injected headers.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/http1.c b/lib/http1.c
index 0000000..0000000 100644
--- a/lib/http1.c
+++ b/lib/http1.c
@@
+static h2o_iovec_t sanitize_reason_phrase(h2o_mem_pool_t *pool, const char *reason)
+{
+    size_t len = strlen(reason), i;
+    char *dst = NULL;
+
+    for (i = 0; i != len; ++i) {
+        if (reason[i] == '\r' || reason[i] == '\n')
+            break;
+    }
+    if (i == len)
+        return h2o_iovec_init((char *)reason, len);
+
+    dst = h2o_mem_alloc_pool(pool, char, len + 1);
+    len = 0;
+    do {
+        if (reason[i] != '\r' && reason[i] != '\n')
+            dst[len++] = reason[i];
+    } while (reason[++i] != '\0');
+    dst[len] = '\0';
+
+    return h2o_iovec_init(dst, len);
+}
@@
-    dst = buffer.base + buffer.len;
-    dst += sprintf(dst, "HTTP/1.1 %d %s\r\n", req->res.status, req->res.reason);
+    h2o_iovec_t sanitized_reason = sanitize_reason_phrase(pool, req->res.reason);
+    dst = buffer.base + buffer.len;
+    dst += sprintf(dst, "HTTP/1.1 %d %.*s\r\n", req->res.status, (int)sanitized_reason.len, sanitized_reason.base);
@@
-    dst += sprintf(dst, "HTTP/1.1 %d %s\r\n", status, reason);
+    h2o_iovec_t sanitized_reason = sanitize_reason_phrase(req->pool, reason);
+    dst += sprintf(dst, "HTTP/1.1 %d %.*s\r\n", status, (int)sanitized_reason.len, sanitized_reason.base);
@@
-    *dst++ = ' ';
-    dst += sprintf(dst, "%s\r\n", req->res.reason);
+    h2o_iovec_t sanitized_reason = sanitize_reason_phrase(req->pool, req->res.reason);
+    *dst++ = ' ';
+    dst += sprintf(dst, "%.*s\r\n", (int)sanitized_reason.len, sanitized_reason.base);
```