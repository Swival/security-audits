# Challenge Credential Errors Reported As Success

## Classification

Medium severity error-handling bug.

## Affected Locations

`modules/ssl/ssl_engine_kernel.c:2196`

## Summary

`set_challenge_creds()` records challenge credential setup failures in `rv`, but always returns `APR_SUCCESS` after cleanup. As a result, ALPN challenge credential failures are reported to the caller as success, so `ssl_callback_alpn_select()` does not send a fatal TLS alert and the handshake can continue without the intended ACME challenge certificate.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- ACME/challenge credential override is selected during ALPN handling.
- A non-`h2` protocol switch occurs and `ssl_is_challenge()` supplies challenge credentials.
- The supplied challenge certificate/key data is malformed, invalid, unusable, or mismatched.

## Proof

Challenge credentials originate from `ssl_is_challenge()` in `ssl_callback_alpn_select()` and flow into `set_challenge_creds()`.

Failure paths in `set_challenge_creds()` set `rv` to a failure value or preserve a failing status, then jump to `cleanup`:

- `modssl_read_cert()` parse failure logs `APLOGNO(10266)` and jumps to `cleanup`.
- `SSL_use_certificate()` failure sets `rv = APR_EGENERAL` and jumps to `cleanup`.
- `SSL_use_PrivateKey()` failure sets `rv = APR_EGENERAL` and jumps to `cleanup`.
- `SSL_check_private_key()` failure sets `rv = APR_EGENERAL` and jumps to `cleanup`.

Before the patch, `cleanup` freed local certificate/key objects and then unconditionally returned `APR_SUCCESS`. Therefore this caller check was bypassed:

```c
if (set_challenge_creds(c, servername, ssl, cert, key,
                        cert_pem, key_pem) != APR_SUCCESS) {
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}
```

The reproduced flow confirms that malformed PEM, invalid key, or certificate/key mismatch reaches these failure paths, but ALPN selection still returns success instead of a fatal alert.

## Why This Is A Real Bug

The function’s local control flow explicitly distinguishes success from failure by maintaining `rv`, but the final return discards that status. This contradicts the caller contract, because `ssl_callback_alpn_select()` only aborts the handshake when `set_challenge_creds()` returns a non-success status.

Practical impact is that the TLS handshake can proceed after failing to install the challenge credential, likely using the previous/default certificate or partially modified SSL state. For ACME TLS-ALPN-01, this causes validation failure while internal handling misleadingly reports credential setup success.

## Fix Requirement

Return the accumulated `rv` from `set_challenge_creds()` after cleanup instead of unconditionally returning `APR_SUCCESS`.

## Patch Rationale

The patch preserves existing cleanup behavior and restores the intended error propagation. Successful paths still return `APR_SUCCESS`; parse, certificate installation, private key installation, and certificate/key mismatch failures now return their recorded failure status to the ALPN callback, which then emits a fatal TLS alert.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/ssl/ssl_engine_kernel.c b/modules/ssl/ssl_engine_kernel.c
index 83ae90e..d117752 100644
--- a/modules/ssl/ssl_engine_kernel.c
+++ b/modules/ssl/ssl_engine_kernel.c
@@ -2193,7 +2193,7 @@ static apr_status_t set_challenge_creds(conn_rec *c, const char *servername,
 cleanup:
     if (our_data && cert) X509_free(cert);
     if (our_data && key) EVP_PKEY_free(key);
-    return APR_SUCCESS;
+    return rv;
 }
   
 /*
```