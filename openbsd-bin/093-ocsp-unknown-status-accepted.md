# OCSP UNKNOWN Status Accepted

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`usr.sbin/ocspcheck/ocspcheck.c:508`

## Summary

`validate_response()` accepted signed OCSP responses whose per-certificate status was `V_OCSP_CERTSTATUS_UNKNOWN`. The function rejected revoked responses, but did not require the status returned by `OCSP_resp_find_status()` to be `V_OCSP_CERTSTATUS_GOOD` before returning success. A trusted OCSP responder could therefore produce a signed `UNKNOWN` response that passed validation and was treated as a valid OCSP staple.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The OCSP responder can produce a response signature trusted by `OCSP_basic_verify()`.
- The OCSP response is otherwise structurally valid and has `OCSP_RESPONSE_STATUS_SUCCESSFUL`.
- The response contains a matching certificate ID.
- `thisUpdate` and `nextUpdate` parse successfully and satisfy the existing freshness checks.
- The per-certificate OCSP status is `V_OCSP_CERTSTATUS_UNKNOWN`.

## Proof

`validate_response()` calls `OCSP_resp_find_status()` to populate `cert_status`, `revtime`, `thisupd`, and `nextupd`.

The original rejection logic only failed when:

- `revtime` parsed as present, or
- `cert_status == V_OCSP_CERTSTATUS_REVOKED`.

It did not reject `V_OCSP_CERTSTATUS_UNKNOWN`. Therefore, a signed response with:

- successful OCSP response status,
- trusted basic response signature,
- matching certificate ID,
- `cert_status = V_OCSP_CERTSTATUS_UNKNOWN`,
- no revocation time,
- valid update timestamps,

continued through the time checks and reached `ret = 1`, causing `main()` to accept or save the response as a valid OCSP staple.

## Why This Is A Real Bug

OCSP certificate status is tri-state: good, revoked, or unknown. `UNKNOWN` is not equivalent to `GOOD`; it means the responder does not know the certificate status. A validator that accepts `UNKNOWN` as success fails open and can treat an indeterminate certificate status as valid.

The reproduced control flow confirms that the committed code accepted any non-revoked status, including `UNKNOWN`, after signature and freshness validation.

## Fix Requirement

Require `cert_status == V_OCSP_CERTSTATUS_GOOD` before returning success from `validate_response()`.

## Patch Rationale

The patch adds an explicit post-revocation status check:

```c
if (cert_status != V_OCSP_CERTSTATUS_GOOD) {
	warnx("Invalid OCSP reply: certificate status is not good");
	goto err;
}
```

This preserves the existing revoked-status handling and revocation-time diagnostics while ensuring that only an affirmative OCSP `GOOD` status can pass validation. `UNKNOWN` and any other non-good status now fail closed.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/ocspcheck/ocspcheck.c b/usr.sbin/ocspcheck/ocspcheck.c
index ae4b836..5ffdcb1 100644
--- a/usr.sbin/ocspcheck/ocspcheck.c
+++ b/usr.sbin/ocspcheck/ocspcheck.c
@@ -481,6 +481,10 @@ validate_response(char *buf, size_t size, ocsp_request *request,
 			warnx("Certificate revoked at: %s", ctime(&rev_t));
 		goto err;
 	}
+	if (cert_status != V_OCSP_CERTSTATUS_GOOD) {
+		warnx("Invalid OCSP reply: certificate status is not good");
+		goto err;
+	}
 	if ((this_t = parse_ocsp_time(thisupd)) == -1) {
 		warnx("unable to parse this update time in OCSP reply");
 		goto err;
```