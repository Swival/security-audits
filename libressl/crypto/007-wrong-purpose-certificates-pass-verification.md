# Wrong-Purpose Certificates Pass Verification

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`x509/x509_verify.c:900`

## Summary

The non-legacy X.509 verifier accepts certificates that fail the configured purpose check. When `ctx->purpose > 0`, `x509_verify_cert_extensions()` incorrectly rejects nonzero `X509_check_purpose()` results and allows zero results. Since `X509_check_purpose()` returns `0` when a certificate is unsuitable for the requested purpose, wrong-purpose certificates can authenticate successfully.

## Provenance

Identified and reproduced from scanner output attributed to Swival Security Scanner: https://swival.dev

## Preconditions

- Verification uses the non-legacy `x509_verify()` path, where `ctx->xsc == NULL`.
- The verifier is configured with `ctx->purpose > 0`.
- A presented certificate chains to a trusted root but lacks the requested purpose, such as a `clientAuth`-only certificate used for `X509_PURPOSE_SSL_SERVER`.

## Proof

`x509_verify_cert_extensions()` implements the purpose authorization check:

```c
if (ctx->purpose > 0 && X509_check_purpose(cert, ctx->purpose, need_ca)) {
	ctx->error = X509_V_ERR_INVALID_PURPOSE;
	return 0;
}
```

This condition is inverted. A certificate with EKU `clientAuth` only causes:

```c
X509_check_purpose(cert, X509_PURPOSE_SSL_SERVER, 0) == 0
```

The buggy condition does not reject that result, so verification continues.

The affected path is reachable through both leaf and chain validation:

- `x509_verify_ctx_add_chain()` calls `x509_verify_cert_valid()` for the leaf before accepting a built chain.
- `x509_verify_consider_candidate()` calls `x509_verify_cert_valid()` for candidate chain certificates.
- `x509_verify_cert_valid()` calls `x509_verify_cert_extensions()`.
- `x509_verify()` later sets `ctx->error = X509_V_OK` whenever `ctx->chains_count > 0`.

Therefore, after a trusted chain is built, a certificate that failed the requested purpose check reaches the success path.

## Why This Is A Real Bug

The purpose check is an authorization control for certificate usage. `X509_check_purpose()` returns a positive value for an acceptable purpose and `0` or a negative value for failure/error. The implementation rejects success and allows the deterministic failure value `0`.

The compatibility path is not the reproduced vulnerable path: when `ctx->xsc != NULL`, `x509_verify_cert_extensions()` returns early and legacy validation uses `x509_vfy_check_chain_extensions()`, which correctly rejects `ret == 0`.

## Fix Requirement

Reject certificates when `X509_check_purpose()` returns `<= 0`, not when it returns success.

## Patch Rationale

The patch changes the non-legacy purpose check to match the expected `X509_check_purpose()` contract. Positive return values are accepted; zero or negative return values set `X509_V_ERR_INVALID_PURPOSE` and stop verification.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_verify.c b/x509/x509_verify.c
index fc3fbc1..306b000 100644
--- a/x509/x509_verify.c
+++ b/x509/x509_verify.c
@@ -911,7 +911,7 @@ x509_verify_cert_extensions(struct x509_verify_ctx *ctx, X509 *cert, int need_ca
 		ctx->error = X509_V_ERR_INVALID_CA;
 		return 0;
 	}
-	if (ctx->purpose > 0 && X509_check_purpose(cert, ctx->purpose, need_ca)) {
+	if (ctx->purpose > 0 && X509_check_purpose(cert, ctx->purpose, need_ca) <= 0) {
 		ctx->error = X509_V_ERR_INVALID_PURPOSE;
 		return 0;
 	}
```