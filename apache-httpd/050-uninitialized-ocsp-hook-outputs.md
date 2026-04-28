# uninitialized OCSP hook outputs

## Classification

Memory safety, medium severity, confidence certain.

## Affected Locations

`modules/ssl/ssl_util_stapling.c:811`

## Summary

`stapling_cb` passed uninitialized stack outputs to OCSP stapling provider hooks. If a `get_stapling_status` hook returned `APR_SUCCESS` without writing both output parameters, `stapling_cb` treated indeterminate `resp.data` and/or `rspderlen` as a valid OCSP response and forwarded them to OpenSSL.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A registered `get_stapling_status` hook returns `APR_SUCCESS` without initializing both `*pder` and `*pderlen`.

## Proof

`stapling_cb` declared:

```c
ocsp_resp resp;
int rspderlen, provided = 0;
```

It then called:

```c
ssl_run_get_stapling_status(&resp.data, &rspderlen, conn, s, x)
```

If that hook returned `APR_SUCCESS`, the code executed:

```c
resp.len = (apr_size_t)rspderlen;
provided = 1;
```

The `provided` path then read `resp.data` and `resp.len`, and could call:

```c
SSL_set_tlsext_status_ocsp_resp(ssl, resp.data, (int)resp.len);
```

The callback is installed as the TLS certificate-status callback and is reached during a normal TLS handshake when a client sends a certificate status request extension.

## Why This Is A Real Bug

The code trusted hook success as proof that both output parameters were initialized. APR hook implementations are external extension points, and a buggy or incomplete provider can legally return control to this code with stack values still indeterminate. Those indeterminate values are then used as a pointer and length for an OCSP response.

Impact depends on stack contents, but the bug can plausibly cause process crash, invalid memory use, invalid free behavior inside OpenSSL ownership handling, or unintended disclosure of memory as stapled OCSP bytes.

## Fix Requirement

Initialize all hook output variables before invoking providers:

- `resp.data` must start as `NULL`.
- `resp.len` must start as `0`.
- `rspderlen` must start as `0`.

## Patch Rationale

The patch makes the failure mode deterministic and safe. If a hook returns `APR_SUCCESS` but fails to populate either output, the existing validation path sees `resp.data == NULL` or `resp.len == 0` and returns `SSL_TLSEXT_ERR_NOACK` instead of passing arbitrary stack-derived values to OpenSSL.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_util_stapling.c b/modules/ssl/ssl_util_stapling.c
index 563de55..8c2add7 100644
--- a/modules/ssl/ssl_util_stapling.c
+++ b/modules/ssl/ssl_util_stapling.c
@@ -808,13 +808,13 @@ static int stapling_cb(SSL *ssl, void *arg)
     SSLSrvConfigRec *sc = mySrvConfig(s);
     modssl_ctx_t *mctx  = myConnCtxConfig(conn, sc);
     UCHAR idx[SHA_DIGEST_LENGTH];
-    ocsp_resp resp;
+    ocsp_resp resp = { NULL, 0 };
     certinfo *cinf = NULL;
     OCSP_RESPONSE *rsp = NULL;
     int rv;
     BOOL ok = TRUE;
     X509 *x;
-    int rspderlen, provided = 0;
+    int rspderlen = 0, provided = 0;
 
     ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, APLOGNO(01951)
                  "stapling_cb: OCSP Stapling callback called");
```