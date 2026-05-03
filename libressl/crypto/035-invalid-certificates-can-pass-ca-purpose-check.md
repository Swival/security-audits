# Invalid Certificates Can Pass CA-Purpose Check

## Classification

Security control failure, high severity.

Confidence: certain.

## Affected Locations

`x509/x509_purp.c:619`

## Summary

`X509_check_ca()` used the extension cache for CA-purpose decisions but ignored cache failure. An invalid X.509 certificate could be marked with `EXFLAG_INVALID` while still retaining `EXFLAG_BCONS | EXFLAG_CA`; `X509_check_ca()` then called `check_ca()` and returned CA status instead of rejecting the invalid certificate.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller trusts `X509_check_ca()` as the CA decision point.

## Proof

An attacker-controlled X.509 v3 certificate can contain:

- one valid `basicConstraints` extension with `CA:TRUE`
- no rejecting `keyUsage`
- duplicate extension OIDs elsewhere

Observed control flow:

- `x509v3_cache_extensions_internal()` decodes `basicConstraints` and sets `EXFLAG_CA` and `EXFLAG_BCONS` at `x509/x509_purp.c:424`.
- The same cache pass later detects duplicate extension OIDs and sets `EXFLAG_INVALID` at `x509/x509_purp.c:565`.
- `x509v3_cache_extensions()` returns false when `EXFLAG_INVALID` is set at `x509/x509_purp.c:580`.
- `X509_check_ca()` ignored that false return at `x509/x509_purp.c:623`.
- `check_ca()` saw `EXFLAG_BCONS | EXFLAG_CA` and returned `1` at `x509/x509_purp.c:598`.

Result: `X509_check_ca()` reported an invalid certificate as a CA.

## Why This Is A Real Bug

`X509_check_ca()` is the exported CA decision function documented as checking whether a certificate can be used to sign other certificates. The extension cache already identified the certificate as invalid, but the CA-purpose check failed open by ignoring that result and relying on partially populated CA flags. This allows invalid certificate structure to bypass the CA-purpose security control when callers depend on `X509_check_ca()`.

## Fix Requirement

`X509_check_ca()` must reject the certificate when `x509v3_cache_extensions(x)` fails.

## Patch Rationale

The patch makes `X509_check_ca()` consistent with other validation paths that treat extension-cache failure as rejection. Returning `0` preserves the function’s meaning of “not a CA” and prevents `check_ca()` from using cached CA bits from a certificate already marked invalid.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_purp.c b/x509/x509_purp.c
index 36dfe6a..fdbc417 100644
--- a/x509/x509_purp.c
+++ b/x509/x509_purp.c
@@ -620,7 +620,8 @@ check_ca(const X509 *x)
 int
 X509_check_ca(X509 *x)
 {
-	x509v3_cache_extensions(x);
+	if (!x509v3_cache_extensions(x))
+		return 0;
 
 	return check_ca(x);
 }
```