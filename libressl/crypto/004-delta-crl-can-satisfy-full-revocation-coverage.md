# Delta CRL Can Satisfy Full Revocation Coverage

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

- `x509/x509_vfy.c:843`
- `x509/x509_vfy.c:1223`
- `x509/x509_vfy.c:1232`
- `x509/x509_vfy.c:1547`
- `x509/x509_vfy.c:1620`
- `x509/x509_vfy.c:1698`

## Summary

`get_crl_score()` can accept a delta CRL as if it were a full CRL when extended CRL support is enabled and the delta CRL has `IDP_REASONS`. The `IDP_REASONS` branch prevents the later `base_crl_number` delta rejection from running. That lets a delta CRL provide full reason coverage, causing revocation checking to stop without consulting the full CRL that contains the revoked certificate serial.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- CRL checking is enabled.
- Extended CRL support is enabled.
- A CA-signed delta CRL is available.
- The delta CRL has `base_crl_number`.
- The delta CRL has `IDP_REASONS` sufficient to cover the remaining reasons.
- The relevant full/base CRL contains the revoked certificate serial, while the selected delta CRL does not.

## Proof

In `get_crl_score()`, the original control flow rejects invalid IDPs, then checks extended CRL support. When `X509_V_FLAG_EXTENDED_CRL_SUPPORT` is set and `crl->idp_flags` contains `IDP_REASONS`, the `else if (crl->idp_flags & IDP_REASONS)` branch runs.

Because the delta rejection was attached as a later `else if (crl->base_crl_number)`, that rejection is skipped for a delta CRL with `IDP_REASONS`.

The delta CRL can then:

- pass issuer, AKID, time, and scope scoring;
- reach `CRL_SCORE_VALID`;
- update `*preasons` through `crl_crldp_check()`;
- be accepted by `get_crl_sk()` when `best_score >= CRL_SCORE_VALID`;
- set `ctx->current_reasons` in `get_crl_delta()`;
- cause `check_cert()` to terminate once `ctx->current_reasons == CRLDP_ALL_REASONS`.

Later validation does not compensate for this selection error. `x509_vfy_check_crl()` skips most checks for CRLs with `base_crl_number`, and `x509_vfy_cert_crl()` searches only the selected CRL for the certificate serial. A revoked certificate present only in the full CRL is therefore accepted.

## Why This Is A Real Bug

A delta CRL is not a standalone full revocation source. It only represents changes relative to a base/full CRL. Treating it as complete coverage violates revocation semantics and creates a fail-open path: a revoked certificate validates if the selected delta CRL omits the serial while the full CRL contains it.

The reproduced path is deterministic under the stated flags and CRL ordering/selection conditions. The failure occurs before cryptographic signature checks can provide protection, because the signed delta CRL is structurally valid but used for the wrong purpose.

## Fix Requirement

Reject CRLs with `base_crl_number` before any `IDP_REASONS` scoring in `get_crl_score()`.

Delta CRLs must not be candidates for the full/base CRL selection stage. They should only be considered later through delta-specific compatibility logic against an already selected base CRL.

## Patch Rationale

The patch moves the `crl->base_crl_number` rejection above the extended CRL support and `IDP_REASONS` branch. This makes the delta rejection unconditional at the start of full CRL scoring.

That preserves intended behavior:

- full CRLs with reason-scoped IDPs remain eligible;
- indirect CRL and reason handling still requires extended CRL support;
- delta CRLs remain available through `get_delta_sk()` and `check_delta_base()`;
- delta CRLs can no longer satisfy full revocation coverage by bypassing the original `else if`.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_vfy.c b/x509/x509_vfy.c
index 7764785..0c6f050 100644
--- a/x509/x509_vfy.c
+++ b/x509/x509_vfy.c
@@ -1223,6 +1223,9 @@ get_crl_score(X509_STORE_CTX *ctx, X509 **pissuer, unsigned int *preasons,
 	/* Invalid IDP cannot be processed */
 	if (crl->idp_flags & IDP_INVALID)
 		return 0;
+	/* Don't process deltas at this stage */
+	if (crl->base_crl_number)
+		return 0;
 	/* Reason codes or indirect CRLs need extended CRL support */
 	if (!(ctx->param->flags & X509_V_FLAG_EXTENDED_CRL_SUPPORT)) {
 		if (crl->idp_flags & (IDP_INDIRECT | IDP_REASONS))
@@ -1232,9 +1235,6 @@ get_crl_score(X509_STORE_CTX *ctx, X509 **pissuer, unsigned int *preasons,
 		if (!(crl->idp_reasons & ~tmp_reasons))
 			return 0;
 	}
-	/* Don't process deltas at this stage */
-	else if (crl->base_crl_number)
-		return 0;
 	/* If issuer name doesn't match certificate need indirect CRL */
 	if (X509_NAME_cmp(X509_get_issuer_name(x), X509_CRL_get_issuer(crl))) {
 		if (!(crl->idp_flags & IDP_INDIRECT))
```