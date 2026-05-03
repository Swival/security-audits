# Inherited ASID Skips Issuer Resource Absence

## Classification

security_control_failure, high severity, confidence certain.

## Affected Locations

`x509/x509_asid.c:1155`

## Summary

`asid_validate_path_internal()` failed to reject an issuer certificate that lacks the RFC3779 AS Identifier extension when the child state is inherited rather than concrete. This let a chain with a lower inherited ASID, an intermediate issuer missing ASID, and a higher ancestor with concrete AS resources validate successfully, despite violating the issuer-extension requirement.

## Provenance

Verified from the supplied reproduction and patch details. Initial scanner provenance: Swival Security Scanner, https://swival.dev.

## Preconditions

A malicious peer can present an RPKI certificate chain with this shape:

- Leaf or lower certificate has an ASID extension with `asnum = inherit` or `rdi = inherit`.
- Its issuer lacks the ASID extension entirely.
- A higher ancestor contains concrete `ASIdsOrRanges`.
- The chain is validated through `asid_validate_path_internal()` via `X509v3_asid_validate_path()` or `X509v3_asid_validate_resource_set()`.

## Proof

The reproduced path shows:

- Documentation states that when an RFC3779 extension is present in a certificate, the same extension type must also be present in its issuer at `man/X509v3_addr_validate_path.3:56`.
- A child ASID extension with `asnum = inherit` sets `inherit_as = 1` while leaving `child_as = NULL` at `x509/x509_asid.c:1125`.
- When the next issuer has no ASID extension, the missing-extension branch at `x509/x509_asid.c:1155` rejects only `child_as != NULL || child_rdi != NULL`.
- Because inherited state is tracked only in `inherit_as` / `inherit_rdi`, the issuer with no ASID extension is skipped.
- A higher ancestor with concrete `ASIdsOrRanges` then passes because `inherit_as || asid_contains(...)` short-circuits true at `x509/x509_asid.c:1168`.
- Inheritance is cleared, `ret` remains `1`, and validation succeeds.

## Why This Is A Real Bug

RFC3779 path validation requires the issuer to carry the relevant resource extension when the child carries it. Inherited ASID is still an active child ASID constraint. Treating `inherit_as` or `inherit_rdi` as absence of child resources during the missing-issuer-extension check creates a fail-open gap.

The validator therefore accepts a chain that should be rejected with `X509_V_ERR_UNNESTED_RESOURCE`, allowing unauthorized AS resource delegation to validate.

## Fix Requirement

When an issuer lacks `x->rfc3779_asid`, validation must reject if any ASID validation state is active:

- concrete AS resources: `child_as != NULL`
- concrete RDI resources: `child_rdi != NULL`
- inherited AS resources: `inherit_as`
- inherited RDI resources: `inherit_rdi`

## Patch Rationale

The patch extends the existing missing-extension rejection condition to include inherited ASID state. This preserves the original concrete-resource behavior while closing the inherited-resource bypass.

The change is minimal and localized to the `x->rfc3779_asid == NULL` branch, where the validator decides whether a missing issuer ASID extension is permissible.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_asid.c b/x509/x509_asid.c
index 45a154e..7c63af6 100644
--- a/x509/x509_asid.c
+++ b/x509/x509_asid.c
@@ -1153,7 +1153,8 @@ asid_validate_path_internal(X509_STORE_CTX *ctx, STACK_OF(X509) *chain,
 		if ((X509_get_extension_flags(x) & EXFLAG_INVALID) != 0)
 			validation_err(X509_V_ERR_INVALID_EXTENSION);
 		if (x->rfc3779_asid == NULL) {
-			if (child_as != NULL || child_rdi != NULL)
+			if (child_as != NULL || child_rdi != NULL ||
+			    inherit_as || inherit_rdi)
 				validation_err(X509_V_ERR_UNNESTED_RESOURCE);
 			continue;
 		}
```