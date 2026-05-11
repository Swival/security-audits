# Cached CA Store Overrides SSL Context Callback

## Classification

Security control failure, high severity.

## Affected Locations

- `lib/vtls/wolfssl.c:603` (`wssl_populate_x509_store` sets `x509_store_setup`)
- `lib/vtls/wolfssl.c:819` (cached store already in `ssl_ctx`)
- `lib/vtls/wolfssl.c:823` (cached store installed via `wolfSSL_CTX_set_cert_store`)
- `lib/vtls/wolfssl.c:1434` (`fsslctx` callback invocation)
- `lib/vtls/wolfssl.c:1719` (`wssl_handshake` re-runs setup when `x509_store_setup` is false)

## Summary

When wolfSSL CA caching is enabled, libcurl can reinstall a cached X509 trust store after an application SSL context callback has changed certificate trust settings. This causes the callback's intended trust restrictions to be overwritten before `wolfSSL_connect()` completes certificate verification.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- CA cache is enabled.
- Peer verification is enabled.
- Cache criteria match an existing cached CA store.
- The application uses `CURLOPT_SSL_CTX_FUNCTION` / SSL context callback to alter trust.
- A TLS handshake occurs after the callback changes certificate trust settings.

## Proof

`Curl_wssl_ctx_init()` invokes `Curl_wssl_setup_x509_store()` before the application SSL context callback when `data->set.ssl.fsslctx` is set.

If a matching cached store exists, `Curl_wssl_setup_x509_store()` installs it with `wolfSSL_CTX_set_cert_store(wssl->ssl_ctx, cached_store)` but does not set `wssl->x509_store_setup`.

The application callback can then replace or restrict the trust store on `wctx->ssl_ctx`.

Later, `wssl_handshake()` checks `!wssl->x509_store_setup` and calls `Curl_wssl_setup_x509_store()` again. If the callback replaced the current store, `wolfSSL_CTX_get_cert_store(wssl->ssl_ctx) == cached_store` is false, so the cached store is reinstalled with `wolfSSL_CTX_set_cert_store()`, overriding the callback's trust decision before certificate verification.

A malicious TLS server with a certificate trusted by the stale cached CA store, but not trusted by the callback's intended store, can complete peer authentication.

## Why This Is A Real Bug

The SSL context callback is an exposed application control point for modifying TLS verification behavior. Reapplying a cached CA store after that callback silently invalidates the application's trust decision.

The failure occurs on the certificate verification path with `verifypeer` enabled. It can cause TLS authentication to accept a peer the application explicitly intended to reject, which is a security-relevant certificate verification bypass.

## Fix Requirement

When a cached X509 store is selected or installed, mark the X509 store as already set up so later handshake logic does not re-run CA store setup and override callback changes.

## Patch Rationale

The patch sets `wssl->x509_store_setup = TRUE` in both cached-store branches:

- cached store is already active
- cached store is installed via `wolfSSL_CTX_set_cert_store()`

This makes the cached-store path consistent with `wssl_populate_x509_store()`, which already marks `x509_store_setup` true for populated stores. After the application SSL context callback returns, `wssl_handshake()` no longer re-enters `Curl_wssl_setup_x509_store()` solely because the cached-store path left the flag false.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/vtls/wolfssl.c b/lib/vtls/wolfssl.c
index 59574c9b6a..9cb85b4427 100644
--- a/lib/vtls/wolfssl.c
+++ b/lib/vtls/wolfssl.c
@@ -819,9 +819,11 @@ CURLcode Curl_wssl_setup_x509_store(struct Curl_cfilter *cf,
   if(cached_store &&
      wolfSSL_CTX_get_cert_store(wssl->ssl_ctx) == cached_store) {
     /* The cached store is already in use, do nothing. */
+    wssl->x509_store_setup = TRUE;
   }
   else if(cached_store && wolfSSL_X509_STORE_up_ref(cached_store)) {
     wolfSSL_CTX_set_cert_store(wssl->ssl_ctx, cached_store);
+    wssl->x509_store_setup = TRUE;
   }
   else if(cache_criteria_met) {
     /* wolfSSL's initial store in CTX is not shareable by default.
```