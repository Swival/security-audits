# Null nonce-count parsing

## Classification

Vulnerability, medium severity. Confidence: certain.

## Affected Locations

`modules/aaa/mod_auth_digest.c:1393`

## Summary

`mod_auth_digest` can dereference a NULL `nonce_count` pointer when nonce-count checking is enabled and a valid RFC-2069-style Digest Authorization header omits both `qop` and `nc`. The crash occurs in `check_nc()` when `strtol()` is called with `resp->nonce_count == NULL`, causing a worker/child process denial of service.

## Provenance

Verified from the supplied source, reproduced execution path, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Digest authentication protects the requested resource.
- `AuthDigestNcCheck On` is configured.
- Shared memory for nonce-count tracking is available and initialized.
- `AuthDigestQop` is not configured as `none`; default qop or `AuthDigestQop auth` is sufficient.
- The client sends a valid RFC-2069-style Digest Authorization header omitting both `qop` and `nc`.
- The password digest check succeeds, requiring valid credentials or an equivalent valid old-style digest.

## Proof

`get_digest_rec()` only requires `nonce_count` when `message_qop` is present:

```c
|| (resp->message_qop && (!resp->cnonce || !resp->nonce_count))
```

A qop-less RFC-2069 Digest header can therefore be accepted as syntactically valid with `resp->nonce_count == NULL`.

`authenticate_digest_user()` accepts qop-less headers through the old digest path:

```c
if (resp->message_qop == NULL) {
    /* old (rfc-2069) style digest */
    if (strcmp(resp->digest, old_digest(r, resp))) {
        ...
    }
}
```

After the old digest check succeeds, `authenticate_digest_user()` calls `check_nc()` unconditionally.

In `check_nc()`, when nonce-count checking is enabled and shared memory is present, qop is not `none`, and `resp->nonce_count` is NULL, the original code reaches:

```c
const char *snc = resp->nonce_count;
...
nc = strtol(snc, &endptr, 16);
```

This passes NULL to `strtol()`, causing a NULL pointer dereference and process crash.

The reproduced path confirms that only `AuthDigestQop none` avoids the crash because that branch returns `OK` when `snc == NULL`.

## Why This Is A Real Bug

The parser intentionally permits RFC-2069 qop-less Digest headers. The authenticator then validates those headers and reaches nonce-count enforcement regardless of whether the header included `nc`. Because nonce-count enforcement assumes `resp->nonce_count` is non-NULL, a valid authenticated request can crash the worker process instead of being rejected cleanly.

This is externally triggerable under the listed configuration and produces denial of service.

## Fix Requirement

When nonce-count checking is active and qop is not `none`, `check_nc()` must reject a missing `nonce_count` before parsing it with `strtol()`.

## Patch Rationale

The patch adds an explicit NULL check for `snc` immediately after the existing qop=`none` exception and before `strtol()`.

This preserves existing behavior for:

- Disabled nonce-count checking.
- Missing shared memory.
- `AuthDigestQop none`, where nonce-count is not allowed and absence is accepted.
- Present but malformed `nc`, which continues through the existing numeric validation path.

For the vulnerable case, the request now fails authentication with an error log instead of dereferencing NULL.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/aaa/mod_auth_digest.c b/modules/aaa/mod_auth_digest.c
index 791cec2..8856dc7 100644
--- a/modules/aaa/mod_auth_digest.c
+++ b/modules/aaa/mod_auth_digest.c
@@ -1397,6 +1397,12 @@ static int check_nc(const request_rec *r, const digest_header_rec *resp,
         return OK;
     }
 
+    if (snc == NULL) {
+        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01773)
+                      "missing nonce count");
+        return !OK;
+    }
+
     nc = strtol(snc, &endptr, 16);
     if (endptr < (snc+strlen(snc)) && !apr_isspace(*endptr)) {
         ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01773)
```