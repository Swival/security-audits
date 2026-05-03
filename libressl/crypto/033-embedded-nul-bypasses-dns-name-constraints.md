# Embedded NUL Bypasses DNS Name Constraints

## Classification

security_control_failure, high severity, confidence certain.

## Affected Locations

`x509/x509_ncons.c:470`

## Summary

The legacy exported `NAME_CONSTRAINTS_check()` path accepted an out-of-subtree DNS subjectAltName when the IA5String contained an embedded NUL before a permitted suffix.

`nc_dns()` treated ASN.1 IA5String DNS names as NUL-terminated C strings. For a DNS SAN such as `evil.com\0.example.com` and a permitted DNS subtree `example.com`, the suffix pointer calculation could land on the trailing permitted suffix, and `strcasecmp()` compared only the post-NUL C string segment. This caused `nc_dns()` to return `X509_V_OK` for a DNS name that should be rejected as invalid or outside the permitted subtree.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A relying party validates a certificate chain using the exported legacy `NAME_CONSTRAINTS_check()` control with DNS `permittedSubtrees`.

## Proof

`NAME_CONSTRAINTS_check()` processes each attacker-issued `x->altname` through `nc_match()`. `nc_match_single()` dispatches `GEN_DNS` names to `nc_dns()`.

The vulnerable code used:

```c
char *baseptr = (char *)base->data;
char *dnsptr = (char *)dns->data;
...
dnsptr += dns->length - base->length;
...
if (strcasecmp(baseptr, dnsptr))
	return X509_V_ERR_PERMITTED_VIOLATION;
```

A parsed ASN.1 IA5String can contain embedded NUL bytes because the generic ASN.1 decoder copies the full content with `ASN1_STRING_set()` and appends a terminator after the encoded content. Therefore the DNS SAN byte string `evil.com\0.example.com` remains length-preserving data, not a C string.

For:

- DNS SAN: `evil.com\0.example.com`
- permitted DNS constraint: `example.com`

`dns->length - base->length` points `dnsptr` at the trailing `example.com`. The preceding byte is `.`, so the component-boundary check passes. Then `strcasecmp("example.com", "example.com")` returns zero, so `nc_dns()` returns `X509_V_OK`.

The modern default chain verification path was confirmed blocked by `x509_constraints_valid_domain_internal()`, which rejects `c == '\0'` in `x509/x509_constraints.c:221`. The reproduced bug is therefore limited to callers of the exported legacy `NAME_CONSTRAINTS_check()` control.

## Why This Is A Real Bug

DNS name constraints are a security boundary: a constrained CA must not be able to issue accepted certificates outside its permitted DNS subtree.

The vulnerable implementation made the authorization decision using C string semantics over ASN.1 string data. ASN.1 IA5String values carry explicit lengths and may contain embedded NUL bytes after decoding. Using `strcasecmp()` on those buffers allowed attacker-controlled bytes before the embedded NUL to be ignored during comparison.

This produces a fail-open result: an attacker-controlled DNS SAN that is not a valid in-subtree DNS name is accepted as matching a permitted subtree.

## Fix Requirement

DNS IA5String comparisons in `nc_dns()` must:

- use explicit ASN.1 lengths for all comparisons;
- reject embedded NUL bytes in the presented DNS name;
- reject embedded NUL bytes in the DNS constraint;
- preserve the existing DNS subtree suffix and label-boundary behavior.

## Patch Rationale

The patch replaces NUL-terminated string assumptions with length-aware handling.

It rejects embedded NUL bytes before any match decision:

```c
if (memchr(baseptr, '\0', base->length) != NULL)
	return X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX;
if (memchr(dnsptr, '\0', dns->length) != NULL)
	return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
```

It treats an empty constraint by checking `base->length == 0` rather than dereferencing `*baseptr`.

It adds an explicit shorter-name rejection when `dns->length < base->length`, preventing a length-aware suffix comparison from reading or matching the wrong span.

It replaces `strcasecmp()` with `strncasecmp(baseptr, dnsptr, base->length)`, so the comparison covers exactly the permitted DNS subtree length and cannot terminate early at embedded NUL data.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_ncons.c b/x509/x509_ncons.c
index f197488..ae74369 100644
--- a/x509/x509_ncons.c
+++ b/x509/x509_ncons.c
@@ -458,11 +458,16 @@ nc_dn(X509_NAME *nm, X509_NAME *base)
 static int
 nc_dns(ASN1_IA5STRING *dns, ASN1_IA5STRING *base)
 {
-	char *baseptr = (char *)base->data;
-	char *dnsptr = (char *)dns->data;
+	const char *baseptr = (const char *)base->data;
+	const char *dnsptr = (const char *)dns->data;
+
+	if (memchr(baseptr, '\0', base->length) != NULL)
+		return X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX;
+	if (memchr(dnsptr, '\0', dns->length) != NULL)
+		return X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
 
 	/* Empty matches everything */
-	if (!*baseptr)
+	if (base->length == 0)
 		return X509_V_OK;
 	/* Otherwise can add zero or more components on the left so
 	 * compare RHS and if dns is longer and expect '.' as preceding
@@ -472,9 +477,10 @@ nc_dns(ASN1_IA5STRING *dns, ASN1_IA5STRING *base)
 		dnsptr += dns->length - base->length;
 		if (baseptr[0] != '.' && dnsptr[-1] != '.')
 			return X509_V_ERR_PERMITTED_VIOLATION;
-	}
+	} else if (dns->length < base->length)
+		return X509_V_ERR_PERMITTED_VIOLATION;
 
-	if (strcasecmp(baseptr, dnsptr))
+	if (strncasecmp(baseptr, dnsptr, base->length) != 0)
 		return X509_V_ERR_PERMITTED_VIOLATION;
 
 	return X509_V_OK;
```