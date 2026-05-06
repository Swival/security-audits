# OCSP UNKNOWN Status Accepted

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`libtls/tls_ocsp.c:288`

## Summary

The OCSP certificate-status verifier accepted `V_OCSP_CERTSTATUS_UNKNOWN` as successful validation. A malicious TLS server that controls the stapled OCSP response could provide an otherwise valid, signed, fresh OCSP response reporting `UNKNOWN`, and the client handshake would continue even though the response did not attest that the certificate was good.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The client enables certificate verification.
- The client processes a server stapled OCSP response.
- The attacker controls the TLS server and the stapled OCSP response.
- The stapled OCSP response is signed, fresh, matches the certificate ID, and reports `V_OCSP_CERTSTATUS_UNKNOWN`.

## Proof

`tls_ocsp_verify_response()` validates the OCSP response signature, response status, certificate ID match, and freshness before making the final certificate-status decision.

After `OCSP_resp_find_status()` fills `cert_status`, the final gate accepted both `V_OCSP_CERTSTATUS_GOOD` and `V_OCSP_CERTSTATUS_UNKNOWN`:

```c
if (cert_status != V_OCSP_CERTSTATUS_GOOD && cert_status !=
    V_OCSP_CERTSTATUS_UNKNOWN) {
```

For `cert_status == V_OCSP_CERTSTATUS_UNKNOWN`, execution skipped the error path and reached `ret = 0`.

`tls_ocsp_process_response_internal()` returned that success value, and `tls_ocsp_verify_cb()` converted `res == 0` into callback success:

```c
return (res == 0) ? 1 : 0;
```

Therefore, the TLS handshake continued despite a stapled OCSP response that did not confirm the certificate was good.

## Why This Is A Real Bug

OCSP `UNKNOWN` is not equivalent to `GOOD`. It means the responder does not know the certificate status, so it cannot be treated as successful revocation checking.

The existing logic was fail-open: it rejected revoked and other non-good statuses, but explicitly allowed `UNKNOWN`. This undermined the OCSP security control because an attacker-controlled server could complete the handshake with a signed, current response that provided no positive certificate-status assurance.

`tls_config_ocsp_require_stapling()` only enforces the presence of a stapled response; it does not add a later rejection for `UNKNOWN`.

## Fix Requirement

Accept only `V_OCSP_CERTSTATUS_GOOD` as successful OCSP certificate status validation. Reject `V_OCSP_CERTSTATUS_UNKNOWN`, `V_OCSP_CERTSTATUS_REVOKED`, and any other non-good status.

## Patch Rationale

The patch removes `V_OCSP_CERTSTATUS_UNKNOWN` from the success condition. The verifier now returns success only when the OCSP certificate status is exactly `V_OCSP_CERTSTATUS_GOOD`.

This preserves the existing validation flow for signature, response status, certificate ID, and freshness, while correcting the final status decision so non-good OCSP statuses fail closed.

## Residual Risk

None

## Patch

```diff
diff --git a/libtls/tls_ocsp.c b/libtls/tls_ocsp.c
index b8d855c..94c7bd1 100644
--- a/libtls/tls_ocsp.c
+++ b/libtls/tls_ocsp.c
@@ -273,8 +273,7 @@ tls_ocsp_verify_response(struct tls *ctx, OCSP_RESPONSE *resp)
 		goto err;
 
 	/* finally can look at status */
-	if (cert_status != V_OCSP_CERTSTATUS_GOOD && cert_status !=
-	    V_OCSP_CERTSTATUS_UNKNOWN) {
+	if (cert_status != V_OCSP_CERTSTATUS_GOOD) {
 		tls_set_errorx(ctx, TLS_ERROR_UNKNOWN,
 		    "ocsp verify failed: revoked cert - %s",
 		    OCSP_crl_reason_str(crl_reason));
```