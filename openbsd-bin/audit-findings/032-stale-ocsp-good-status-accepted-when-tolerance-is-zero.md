# Stale OCSP GOOD Status Accepted When Tolerance Is Zero

## Classification

security_control_failure

Severity: high

Confidence: certain

## Affected Locations

- `sbin/iked/ocsp.c:557`
- `sbin/iked/ocsp.c:573`
- `sbin/iked/ocsp.c:581`
- `sbin/iked/ocsp.c:614`

## Summary

`ocsp_parse_response()` skipped OCSP response freshness validation whenever `env->sc_ocsp_tolerate` was zero. A zero tolerance should mean no clock skew tolerance, not no validity checking. Because stale signed OCSP `GOOD` responses could still pass signature verification and status matching, an on-path attacker could replay an old matching `GOOD` response and cause iked to authenticate a certificate whose OCSP status should no longer be accepted.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `sc_ocsp_tolerate` is zero.
- The attacker can replay a signed OCSP response matching the certificate ID.
- The replayed response has status `V_OCSP_CERTSTATUS_GOOD`.
- The replayed response is stale according to `thisUpdate` / `nextUpdate`.

## Proof

The verifier flow in `sbin/iked/ocsp.c` accepted stale responses when tolerance was zero:

- `OCSP_check_nonce()` accepted absent nonces, so replay was not blocked by nonce enforcement.
- `OCSP_basic_verify()` verified the signed OCSP response.
- `OCSP_resp_find_status()` extracted the matching certificate status.
- Freshness validation was guarded by `env->sc_ocsp_tolerate`, so `sc_ocsp_tolerate == 0` skipped `OCSP_check_validity()`.
- `V_OCSP_CERTSTATUS_GOOD` set `valid = 1`.
- `ocsp_validate_finish()` converted `valid = 1` into `IMSG_CERTVALID`.

A harness confirmed the bug: a signed `GOOD` OCSP response with `thisUpdate=Jan 2 2020` and `nextUpdate=Jan 3 2020` caused `OCSP_check_validity(0,-1)=0`, but the iked-equivalent control flow returned `iked_valid_when_tolerate_zero=1`.

## Why This Is A Real Bug

OCSP freshness is part of revocation validation. `sc_ocsp_tolerate == 0` is a valid strict configuration meaning zero accepted clock skew. It must not disable `thisUpdate` / `nextUpdate` validation entirely.

The existing branch inverted that meaning: strict tolerance produced fail-open behavior for stale responses. Since no nonce is required, a stale signed matching `GOOD` response can be replayed by an on-path attacker and accepted as current revocation evidence.

## Fix Requirement

Always call `OCSP_check_validity()` after a matching OCSP status is found. Pass `env->sc_ocsp_tolerate` directly as the allowed skew value, including zero.

## Patch Rationale

The patch removes the `env->sc_ocsp_tolerate &&` guard and preserves the existing call arguments:

```c
if (!OCSP_check_validity(thisupd, nextupd, env->sc_ocsp_tolerate,
    env->sc_ocsp_maxage)) {
```

This makes zero tolerance strict instead of disabling validation. Nonzero tolerance behavior is unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/ocsp.c b/sbin/iked/ocsp.c
index 91c44fc..b1e2c71 100644
--- a/sbin/iked/ocsp.c
+++ b/sbin/iked/ocsp.c
@@ -570,8 +570,7 @@ ocsp_parse_response(struct iked_ocsp *ocsp, OCSP_RESPONSE *resp)
 		errstr = "no status found";
 		goto done;
 	}
-	if (env->sc_ocsp_tolerate &&
-	    !OCSP_check_validity(thisupd, nextupd, env->sc_ocsp_tolerate,
+	if (!OCSP_check_validity(thisupd, nextupd, env->sc_ocsp_tolerate,
 	    env->sc_ocsp_maxage)) {
 		ca_sslerror(SPI_SH(&ocsp->ocsp_sh, __func__));
 		errstr = "status times invalid";
```