# Fake Authorization Header Logged

## Classification

Medium severity vulnerability: sensitive credential disclosure through logs.

## Affected Locations

`modules/aaa/mod_auth_basic.c:436`

## Summary

When `AuthBasicFake` is enabled, `authenticate_basic_fake()` builds a fake Basic `Authorization` header from configured user and password expressions. The previous log message emitted the complete generated header value at info level, exposing base64-encoded credential material to anyone with access to error logs.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `AuthBasicFake` is enabled.
- A request reaches the fake authentication fixup hook.
- The configured fake username and password expressions evaluate to non-empty strings.
- Logging configuration permits module info-level messages.

## Proof

`authenticate_basic_fake()` evaluates the configured fake username and password expressions, concatenates them as `user:pass`, base64-encodes that value, prefixes it with `Basic `, and stores it in the request `Authorization` header.

The vulnerable log statement then writes the complete generated header:

```c
ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02457)
              "AuthBasicFake: \"Authorization: %s\"",
              auth_line);
```

A request under a configuration such as `AuthBasicFake someUser someSecret` therefore causes an info-level error-log entry containing:

```text
Authorization: Basic <base64(someUser:someSecret)>
```

Basic authentication base64 is reversible and represents credential material.

## Why This Is A Real Bug

The fake authorization header is intentionally constructed from configured credential expressions. Logging the complete header discloses the generated credential value. If the fake password is a backend credential or expression-derived secret, log readers can recover and use it. The value is not protected by hashing or encryption; base64 only encodes the bytes.

## Fix Requirement

Do not log the generated `Authorization` header value. Log only that the fake authorization header was set, or omit the log entry entirely.

## Patch Rationale

The patch preserves the existing behavior of setting the fake `Authorization` header while removing the sensitive value from the log message. Operational visibility remains: administrators can still see that `AuthBasicFake` set a header, without exposing credentials.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_auth_basic.c b/modules/aaa/mod_auth_basic.c
index c8c9492..8a8b068 100644
--- a/modules/aaa/mod_auth_basic.c
+++ b/modules/aaa/mod_auth_basic.c
@@ -481,8 +481,7 @@ static int authenticate_basic_fake(request_rec *r)
     apr_table_setn(r->headers_in, "Authorization", auth_line);
 
     ap_log_rerror(APLOG_MARK, APLOG_INFO, 0, r, APLOGNO(02457)
-                  "AuthBasicFake: \"Authorization: %s\"",
-                  auth_line);
+                  "AuthBasicFake: Authorization header set");
 
     return OK;
 }
```