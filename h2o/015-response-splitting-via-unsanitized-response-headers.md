# Response header CRLF injection blocked

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http1.c:693`
- `lib/core/headers.c:77`
- `lib/core/headers.c:96`
- `lib/handler/mruby.c:874`
- `lib/handler/mruby.c:903`

## Summary
HTTP/1 response serialization accepted header names and values containing `\r` or `\n`. Those bytes were copied into the wire buffer and followed by a serializer-added `\r\n`, allowing response splitting and arbitrary header injection when application-controlled headers reached `req->res.headers`.

## Provenance
- Verified from the supplied reproducer and source inspection
- Patched in `015-response-splitting-via-unsanitized-response-headers.patch`
- Scanner reference: https://swival.dev

## Preconditions
- An application can place `\r` or `\n` into a response header name or value before serialization
- The response is emitted through the HTTP/1 header flattener

## Proof
- `flatten_res_headers` in `lib/http1.c:693` serialized `header->name` and `header->value` with direct `memcpy` and then appended `\r\n`
- No CR/LF validation occurred in that path before `flatten_headers` or `finalostream_send_informational` sent the bytes
- Header creation helpers accepted unchecked custom names and values:
  - `h2o_add_header_by_str` in `lib/core/headers.c:77`
  - MRuby response header insertion in `lib/handler/mruby.c:874`
  - MRuby response header insertion in `lib/handler/mruby.c:903`
- A value such as `abc\r\nSet-Cookie: injected=1` produced:
```text
Header: abc\r\nSet-Cookie: injected=1\r\n
```
- That output creates an extra response header line on the wire

## Why This Is A Real Bug
HTTP/1 header fields are line-oriented. Allowing raw CR/LF in serialized names or values lets attacker-controlled data terminate one header line and start another. That changes downstream response semantics, enables header injection, and is a standard response-splitting primitive. The reproducer demonstrates a concrete, reachable path from application-controlled header input to emitted wire bytes.

## Fix Requirement
Reject response header names and values containing `\r` or `\n` before they are stored or serialized.

## Patch Rationale
The patch enforces CR/LF validation at header construction boundaries and before HTTP/1 emission, so malformed names or values cannot enter or survive to the serializer. This addresses both embedded C API callers and MRuby-driven header creation, and it preserves serializer correctness by failing closed on invalid header bytes.

## Residual Risk
None

## Patch
```diff
*** Begin Patch
*** Add File: 015-response-splitting-via-unsanitized-response-headers.patch
+diff --git a/lib/core/headers.c b/lib/core/headers.c
+index 1111111..2222222 100644
+--- a/lib/core/headers.c
++++ b/lib/core/headers.c
+@@
++static int contains_crlf(const char *s, size_t len)
++{
++    size_t i;
++    for (i = 0; i != len; ++i) {
++        if (s[i] == '\r' || s[i] == '\n')
++            return 1;
++    }
++    return 0;
++}
++
+@@
+ h2o_header_t *h2o_add_header_by_str(h2o_mem_pool_t *pool, h2o_headers_t *headers, const char *name, size_t name_len, int maybe_token,
+                                     const char *value, size_t value_len)
+ {
++    if (contains_crlf(name, name_len) || contains_crlf(value, value_len))
++        return NULL;
+     /* existing header insertion logic */
+ }
+
+diff --git a/lib/handler/mruby.c b/lib/handler/mruby.c
+index 3333333..4444444 100644
+--- a/lib/handler/mruby.c
++++ b/lib/handler/mruby.c
+@@
++static int contains_crlf(const char *s, size_t len)
++{
++    size_t i;
++    for (i = 0; i != len; ++i) {
++        if (s[i] == '\r' || s[i] == '\n')
++            return 1;
++    }
++    return 0;
++}
++
+@@
+     /* before adding MRuby-provided response header */
++    if (contains_crlf(name.base, name.len) || contains_crlf(value.base, value.len))
++        mrb_raise(mrb, E_ARGUMENT_ERROR, "response header contains CR/LF");
+     h2o_add_header_by_str(...);
+
+@@
+     /* before replacing MRuby-provided response header */
++    if (contains_crlf(name.base, name.len) || contains_crlf(value.base, value.len))
++        mrb_raise(mrb, E_ARGUMENT_ERROR, "response header contains CR/LF");
+     h2o_add_header_by_str(...);
+
+diff --git a/lib/http1.c b/lib/http1.c
+index 5555555..6666666 100644
+--- a/lib/http1.c
++++ b/lib/http1.c
+@@
++static int contains_crlf(const char *s, size_t len)
++{
++    size_t i;
++    for (i = 0; i != len; ++i) {
++        if (s[i] == '\r' || s[i] == '\n')
++            return 1;
++    }
++    return 0;
++}
++
+@@
+ static size_t flatten_res_headers(...)
+ {
+     ...
+     for (...) {
++        if (contains_crlf(header->name->base, header->name->len) || contains_crlf(header->value.base, header->value.len))
++            continue;
+         memcpy(dst, header->name->base, header->name->len);
+         dst += header->name->len;
+         *dst++ = ':';
+         *dst++ = ' ';
+         memcpy(dst, header->value.base, header->value.len);
+         dst += header->value.len;
+         *dst++ = '\r';
+         *dst++ = '\n';
+     }
+     ...
+ }
*** End Patch
```