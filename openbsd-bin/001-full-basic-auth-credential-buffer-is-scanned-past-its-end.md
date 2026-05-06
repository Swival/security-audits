# Basic Auth Credential Buffer Overread

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`httpd/server_http.c:146`

## Summary

`server_http_authenticate()` decodes Basic authentication credentials into a 1024-byte stack buffer and then searches it with `strchr()` as if it is always NUL-terminated. When `b64_pton()` fills the entire buffer with nonzero bytes and does not append a terminator, `strchr(decoded, ':')` reads past the end of `decoded`.

## Provenance

Verified from the provided source, reproduced with an ASan harness, and patched from a finding reported by Swival Security Scanner: https://swival.dev

## Preconditions

A request reaches a server location with Basic authentication enabled through `SRVFLAG_AUTH`.

## Proof

`server_response()` invokes `server_http_authenticate()` for authenticated locations.

Inside `server_http_authenticate()`:

- `decoded[1024]` is allocated on the stack.
- The buffer is zeroed with `memset(decoded, 0, sizeof(decoded))`.
- `b64_pton()` is called with the full destination size: `sizeof(decoded)`.
- If the decoded credential is exactly 1024 nonzero bytes and contains no colon, no NUL byte remains in `decoded`.
- `strchr(decoded, ':')` then treats `decoded` as a C string and scans beyond the stack buffer until it encounters `:` or `\0`.

A remote unauthenticated client can send an `Authorization: Basic <base64>` header where `<base64>` decodes to exactly 1024 nonzero bytes without `:`. The base64 encoding for 1024 `A` bytes is 1368 bytes, which is below `SERVER_MAXHEADERLENGTH` 8192.

An ASan harness using the same `b64_pton()` / `strchr()` pattern with 1024 decoded `A` bytes reports a stack-buffer-overflow read at `strchr`.

## Why This Is A Real Bug

`b64_pton()` returns the decoded byte count and does not guarantee a trailing NUL when the output exactly fills the destination. The subsequent `strchr()` requires a NUL-terminated string. Therefore, a valid Basic auth header can cause a deterministic read past the stack buffer boundary before authentication fails.

The trigger is remotely reachable before successful authentication and only requires the protected location to have Basic authentication enabled.

## Fix Requirement

Ensure the decoded credential buffer remains NUL-terminated before using string functions, or search only within the decoded length using a bounded operation such as `memchr()`.

## Patch Rationale

The patch reserves one byte in `decoded` for the existing zero terminator by changing the `b64_pton()` destination length from `sizeof(decoded)` to `sizeof(decoded) - 1`.

Because `decoded` is zeroed before decoding, limiting the decoder to 1023 bytes guarantees `decoded[1023]` remains `\0`. `strchr(decoded, ':')` can no longer scan past the stack buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/httpd/server_http.c b/httpd/server_http.c
index b01e018..3a57a5b 100644
--- a/httpd/server_http.c
+++ b/httpd/server_http.c
@@ -145,7 +145,7 @@ server_http_authenticate(struct server_config *srv_conf, struct client *clt)
 		goto done;
 
 	if (b64_pton(strchr(ba->kv_value, ' ') + 1, (uint8_t *)decoded,
-	    sizeof(decoded)) <= 0)
+	    sizeof(decoded) - 1) <= 0)
 		goto done;
 
 	if ((clt_pass = strchr(decoded, ':')) == NULL)
```