# Embedded NUL Bypasses Email Name Constraints

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`x509/x509_ncons.c:490`

## Summary

`nc_email()` treated ASN.1 `IA5STRING` email names as NUL-terminated C strings. An attacker-controlled `rfc822Name` containing an embedded NUL before an unpermitted suffix could satisfy a permitted email subtree comparison even though the full ASN.1 value was outside the permitted subtree.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- A verifier applies email `permittedSubtrees` name constraints to an attacker-issued certificate.
- The attacker can place an embedded NUL byte in an `rfc822Name` `ASN1_IA5STRING`.
- The permitted email subtree is evaluated through `NAME_CONSTRAINTS_check()` and `nc_email()`.

## Proof

`NAME_CONSTRAINTS_check()` evaluates certificate names through `nc_match()`, which dispatches `GEN_EMAIL` constraints through `nc_match_single()` to `nc_email()`.

Before the patch, `nc_email()` did this:

```c
const char *baseptr = (char *)base->data;
const char *emlptr = (char *)eml->data;
const char *baseat = strchr(baseptr, '@');
const char *emlat = strchr(emlptr, '@');
...
if (strcasecmp(baseptr, emlptr))
	return X509_V_ERR_PERMITTED_VIOLATION;
```

For permitted base `allowed.com` and candidate `rfc822Name` bytes:

```text
user@allowed.com\0.evil.com
```

the ASN.1 length still includes `.evil.com`, but C string functions stop at the embedded NUL. `strchr()` finds `@`, then `strcasecmp("allowed.com", "allowed.com\0.evil.com")` returns equal. `nc_email()` therefore returns `X509_V_OK`.

The ASN.1 decoding path preserves the full byte sequence: `rfc822Name` is decoded as `ASN1_IA5STRING` in `x509/x509_genn.c:194`, and `ASN1_STRING_set()` copies the full DER length while appending an extra terminator in `asn1/a_string.c:187`.

## Why This Is A Real Bug

The security decision is supposed to apply to the complete ASN.1 `rfc822Name` value. Instead, the previous implementation evaluated only the prefix before the first NUL byte. This causes a deterministic fail-open in email name constraints: a value outside the permitted subtree is accepted as inside it.

The example `user@allowed.com\0.evil.com` is not equivalent to `user@allowed.com` when evaluated over its actual ASN.1 length, but the previous C-string comparison treated it as equivalent.

## Fix Requirement

Reject embedded NUL bytes in the email constraint base and candidate `ASN1_IA5STRING`, or rewrite the matching logic to use explicit lengths for every search and comparison.

## Patch Rationale

The patch rejects any NUL byte within `base->length` or `eml->length` before calling C-string functions:

```c
if (memchr(baseptr, '\0', base->length) != NULL ||
    memchr(emlptr, '\0', eml->length) != NULL)
	return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
```

After this validation, the existing `strchr()`, `strncmp()`, and `strcasecmp()` operations cannot be truncated by attacker-controlled embedded NUL bytes inside the ASN.1 value. Returning `X509_V_ERR_UNSUPPORTED_NAME_SYNTAX` also fails closed for malformed email names.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_ncons.c b/x509/x509_ncons.c
index f197488..24d4a9e 100644
--- a/x509/x509_ncons.c
+++ b/x509/x509_ncons.c
@@ -485,9 +485,15 @@ nc_email(ASN1_IA5STRING *eml, ASN1_IA5STRING *base)
 {
 	const char *baseptr = (char *)base->data;
 	const char *emlptr = (char *)eml->data;
-	const char *baseat = strchr(baseptr, '@');
-	const char *emlat = strchr(emlptr, '@');
+	const char *baseat;
+	const char *emlat;
 
+	if (memchr(baseptr, '\0', base->length) != NULL ||
+	    memchr(emlptr, '\0', eml->length) != NULL)
+		return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
+
+	baseat = strchr(baseptr, '@');
+	emlat = strchr(emlptr, '@');
 	if (!emlat)
 		return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
 	/* Special case: initial '.' is RHS match */
```