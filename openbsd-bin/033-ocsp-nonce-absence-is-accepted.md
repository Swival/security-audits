# OCSP Nonce Absence Is Accepted

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`sbin/iked/ocsp.c:534`

## Summary

`ocsp_parse_response()` accepted OCSP responses that lacked a nonce. When `OCSP_check_nonce(ocsp->ocsp_req, bs)` returned `-1`, the code logged `"no nonce in response"` but continued verification. A replayed, signed, nonce-less OCSP `GOOD` response could therefore pass signature verification, match the requested certificate ID, set `valid = 1`, and send `IMSG_CERTVALID`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- OCSP validation is enabled for certificate authentication.
- An attacker can intercept OCSP traffic to the responder.
- The attacker can provide a signed OCSP response without a nonce.
- The replayed response is otherwise signature-valid and reports `V_OCSP_CERTSTATUS_GOOD`.

## Proof

The vulnerable path in `sbin/iked/ocsp.c` was:

```c
status = OCSP_check_nonce(ocsp->ocsp_req, bs);
if (status <= 0) {
	if (status == -1)
		log_warnx("%s: no nonce in response",
		    SPI_SH(&ocsp->ocsp_sh, __func__));
	else {
		errstr = "nonce verify error";
		goto done;
	}
}
```

For `status == -1`, execution continued into:

```c
status = OCSP_basic_verify(bs, verify_other, store, verify_flags);
```

Then, if the response matched the requested certificate ID and reported `GOOD`:

```c
if (!OCSP_resp_find_status(bs, ocsp->ocsp_id, &status, &reason,
    &rev, &thisupd, &nextupd)) {
	errstr = "no status found";
	goto done;
}

if (status == V_OCSP_CERTSTATUS_GOOD) {
	valid = 1;
}
```

Finally:

```c
cmd = valid ? IMSG_CERTVALID : IMSG_CERTINVALID;
```

The reproducer confirmed this reaches certificate validation when OCSP is enabled: `ca.c` calls `ocsp_validate_cert()` after chain validation, and `IMSG_CERTVALID` causes IKEv2 to mark the peer certificate valid and continue authentication.

## Why This Is A Real Bug

OCSP nonce validation is a freshness control. Accepting nonce-less responses fails open and permits replay of an older signed `GOOD` status. An on-path attacker can use such a replay to defeat revocation checking, causing iked to accept a certificate that should no longer authenticate the peer.

The reproduced behavior confirms that nonce-less replayed OCSP `GOOD` statuses can be accepted and used to validate a revoked peer certificate.

## Fix Requirement

Reject OCSP responses when `OCSP_check_nonce()` reports nonce absence with `status == -1`. The function must stop processing before signature verification, status lookup, and `IMSG_CERTVALID` emission.

## Patch Rationale

The patch changes the `status == -1` branch from log-and-continue to log-and-fail:

```diff
 status = OCSP_check_nonce(ocsp->ocsp_req, bs);
 if (status <= 0) {
-	if (status == -1)
+	if (status == -1) {
 		log_warnx("%s: no nonce in response",
 		    SPI_SH(&ocsp->ocsp_sh, __func__));
-	else {
+		errstr = "no nonce in response";
+	} else
 		errstr = "nonce verify error";
-		goto done;
-	}
+	goto done;
 }
```

This ensures nonce absence follows the same failure path as other nonce verification errors. `valid` remains `0`, cleanup runs, and `ocsp_validate_finish(ocsp, valid)` sends `IMSG_CERTINVALID` instead of `IMSG_CERTVALID`.

## Residual Risk

None

## Patch

`033-ocsp-nonce-absence-is-accepted.patch`

```diff
diff --git a/sbin/iked/ocsp.c b/sbin/iked/ocsp.c
index 91c44fc..7ad1a9b 100644
--- a/sbin/iked/ocsp.c
+++ b/sbin/iked/ocsp.c
@@ -545,13 +545,13 @@ ocsp_parse_response(struct iked_ocsp *ocsp, OCSP_RESPONSE *resp)
 
 	status = OCSP_check_nonce(ocsp->ocsp_req, bs);
 	if (status <= 0) {
-		if (status == -1)
+		if (status == -1) {
 			log_warnx("%s: no nonce in response",
 			    SPI_SH(&ocsp->ocsp_sh, __func__));
-		else {
+			errstr = "no nonce in response";
+		} else
 			errstr = "nonce verify error";
-			goto done;
-		}
+		goto done;
 	}
 
 	store = X509_STORE_new();
```