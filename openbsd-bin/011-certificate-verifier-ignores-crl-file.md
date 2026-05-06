# Certificate Verifier Ignores CRL File

## Classification

security_control_failure, high severity, certain confidence

## Affected Locations

`smtpd/ca.c:130`

## Summary

`ca_X509_verify` accepts a `CRLfile` argument but did not load that CRL into the `X509_STORE` or enable OpenSSL CRL verification flags before calling `X509_verify_cert`. A revoked peer certificate that otherwise chains to the configured trusted CA could therefore verify successfully.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller supplies both `CAfile` and `CRLfile` to `ca_X509_verify`.
- TLS peer presents a revoked certificate.
- The revoked certificate otherwise chains to the trusted CA in `CAfile`.
- The configured CRL contains the certificate revocation entry.

## Proof

`ca_X509_verify` is the certificate verification decision point.

Before the patch:

- `smtpd/ca.c:131` accepted `CRLfile`.
- `smtpd/ca.c:142` loaded only `CAfile` with `X509_STORE_load_locations(store, CAfile, NULL)`.
- `smtpd/ca.c:146` added default paths with `X509_STORE_set_default_paths(store)`.
- No code loaded `CRLfile` into the `X509_STORE`.
- No code enabled `X509_V_FLAG_CRL_CHECK` or `X509_V_FLAG_CRL_CHECK_ALL`.
- `smtpd/ca.c:154` called `X509_verify_cert(xsc)` without revocation data.
- If chain validation succeeded, `smtpd/ca.c:170` returned success.

Runtime reproduction matched the failure mode: a generated revoked leaf certificate verified as `OK` with CA-only verification, but failed with `error 23 ... certificate revoked` once CRL loading and CRL checking were enabled.

## Why This Is A Real Bug

The function signature and caller-provided `CRLfile` indicate revocation checking is expected. Ignoring that file makes the verifier fail open for revoked certificates. This defeats a configured certificate revocation security control and permits a revoked TLS peer certificate to be accepted as valid.

## Fix Requirement

When `CRLfile` is provided, `ca_X509_verify` must:

- Load the CRL file into the `X509_STORE`.
- Fail verification if the CRL cannot be loaded.
- Enable OpenSSL CRL checking flags before `X509_verify_cert`.
- Preserve existing behavior when `CRLfile` is `NULL`.

## Patch Rationale

The patch adds OpenSSL verification declarations via `<openssl/x509_vfy.h>`, creates an `X509_LOOKUP` for file-based CRL loading, loads the supplied PEM CRL with `X509_load_crl_file`, and enables `X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL`.

This makes revocation data available to OpenSSL and requires CRL validation during certificate chain verification. If the CRL cannot be loaded, verification exits through the existing failure path and reports the OpenSSL/logged error.

## Residual Risk

None

## Patch

```diff
diff --git a/smtpd/ca.c b/smtpd/ca.c
index b41d655..247a1ef 100644
--- a/smtpd/ca.c
+++ b/smtpd/ca.c
@@ -19,6 +19,7 @@
 
 #include <openssl/err.h>
 #include <openssl/pem.h>
+#include <openssl/x509_vfy.h>
 #include <pwd.h>
 #include <signal.h>
 #include <string.h>
@@ -131,6 +132,7 @@ int
 ca_X509_verify(void *certificate, void *chain, const char *CAfile,
     const char *CRLfile, const char **errstr)
 {
+	X509_LOOKUP    *lookup = NULL;
 	X509_STORE     *store = NULL;
 	X509_STORE_CTX *xsc = NULL;
 	int		ret = 0;
@@ -145,6 +147,17 @@ ca_X509_verify(void *certificate, void *chain, const char *CAfile,
 	}
 	X509_STORE_set_default_paths(store);
 
+	if (CRLfile != NULL) {
+		if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL)
+			goto end;
+		if (!X509_load_crl_file(lookup, CRLfile, X509_FILETYPE_PEM)) {
+			log_warn("warn: unable to load CRL file %s", CRLfile);
+			goto end;
+		}
+		X509_STORE_set_flags(store,
+		    X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL);
+	}
+
 	if ((xsc = X509_STORE_CTX_new()) == NULL)
 		goto end;
```