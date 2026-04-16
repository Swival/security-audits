# CRLF injection in HTTP/1 request target and Host header

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/common/http1client.c:544`

## Summary
The HTTP/1 client serialized caller-controlled `url->path` into the request target and `url->authority` into both the absolute-form request target and the `host:` header without rejecting CR (`\r`) or LF (`\n`). An attacker who can supply these URL components can inject additional request or header lines on the wire.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Reachability confirmed through the MRuby outbound HTTP client path in `lib/handler/mruby/http_request.c:553` and `lib/handler/mruby/http_request.c:607`
- Scanner reference: https://swival.dev

## Preconditions
- Caller supplies a URL path or authority containing CR or LF
- The request is sent through the HTTP/1 client serialization path

## Proof
- `on_connect` passes the caller-controlled URL into request construction
- `build_request` appends `url->path` directly into the request line and `url->authority` into the absolute-form target and `host:` header using raw `APPEND`, then emits `\r\n` delimiters
- No validation strips or rejects CR/LF before serialization
- Because `h2o_url_parse` accepts these bytes syntactically in relevant fields, and MRuby request construction forwards parsed URLs unchanged, embedded CR/LF reaches the wire and creates injected header/request lines

## Why This Is A Real Bug
HTTP/1 message framing relies on CRLF as structural delimiters. Allowing untrusted CR/LF inside the request target or `Host` value breaks that framing and lets attacker input terminate the current line early, then append arbitrary headers or alter downstream parsing. This is a concrete request-splitting and header-injection vulnerability, not a theoretical parser discrepancy.

## Fix Requirement
Reject or percent-encode CR and LF in `url->path` and `url->authority` before they are appended to the outbound HTTP/1 request buffer.

## Patch Rationale
The patch in `006-crlf-injection-in-request-target-and-host-header.patch` closes the bug at the serialization boundary in `lib/common/http1client.c`, where the vulnerable bytes are emitted. Validating `url->path` and `url->authority` there ensures all HTTP/1 callers are protected, including the confirmed MRuby reachability path.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/common/http1client.c b/lib/common/http1client.c
--- a/lib/common/http1client.c
+++ b/lib/common/http1client.c
@@
+static int contains_crlf(h2o_iovec_t s)
+{
+    size_t i;
+    for (i = 0; i != s.len; ++i) {
+        if (s.base[i] == '\r' || s.base[i] == '\n')
+            return 1;
+    }
+    return 0;
+}
@@
 static h2o_iovec_t build_request(h2o_mem_pool_t *pool, h2o_httpclient__h1_conn_t *conn, h2o_url_t *url, const char *method,
                                  h2o_header_t *headers, size_t num_headers, h2o_iovec_t body, int use_proxy_protocol,
                                  int *reprocess_if_too_early)
 {
+    if (contains_crlf(url->path) || contains_crlf(url->authority))
+        return h2o_iovec_init(NULL, 0);
+
     h2o_iovec_t buf;
     char *dst;
```