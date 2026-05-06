# trailing-dot wildcard matches top-level domain

## Classification

security_control_failure, high severity

## Affected Locations

`libtls/tls_verify.c:61`

## Summary

`tls_match_name()` accepted a wildcard dNSName for a top-level domain when the certificate name ended with a trailing dot. A malicious TLS peer with a trusted `*.com.` certificate could satisfy verification for `victim.com.` because the wildcard validation treated the trailing root dot as evidence of an additional domain label.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

- Caller verifies a hostname with a trailing dot.
- Peer presents a trusted certificate containing a wildcard dNSName such as `*.com.`.
- Verification reaches `tls_match_name()` through subjectAltName or commonName matching.

## Proof

For `cert_name = "*.com."`:

- `cert_domain = &cert_name[1]` produces `.com.`
- `next_dot = strchr(&cert_domain[1], '.')` finds the trailing dot after `com`
- The existing `next_dot == NULL` rejection for `*.bar` is bypassed
- `next_dot[1]` is `'\0'`, so the existing `*.bar..` rejection is also bypassed

For `name = "victim.com."`:

- `domain = strchr(name, '.')` produces `.com.`
- `strcasecmp(cert_domain, domain)` returns equal
- `tls_match_name("*.com.", "victim.com.")` returns success
- `tls_check_subject_altname()` then sets `*alt_match = 1`
- `tls_check_name()` returns success to its caller

The reproduced copied-function PoC confirmed:

```c
tls_match_name("*.com.", "victim.com.") == 0
tls_match_name("*.com", "victim.com") == -1
```

## Why This Is A Real Bug

The verifier already intends to reject top-level wildcards, as shown by the existing comment and check for `*.bar`. A trailing dot does not add a real registrable domain label; it denotes the DNS root. Treating that trailing dot as the required second dot allows an invalid top-level wildcard to pass hostname verification.

Although the normal client connect path strips trailing dots before handshake verification at `libtls/tls_client.c:314`, the underlying certificate-name verifier still deterministically accepts the invalid case when called with a trailing-dot reference name, including through exposed certificate-name checking paths.

## Fix Requirement

Reject wildcard certificate domains where the only dot after the leading wildcard label is the trailing root dot. Specifically, after finding `next_dot`, reject when `next_dot[1] == '\0'`.

## Patch Rationale

The patch extends the existing top-level wildcard rejection from only `*.bar` to both `*.bar` and `*.bar.`:

```diff
-		/* Disallow "*.bar" */
-		if (next_dot == NULL)
+		/* Disallow "*.bar" and "*.bar." */
+		if (next_dot == NULL || next_dot[1] == '\0')
 			return -1;
```

This preserves valid wildcard forms such as `*.domain.tld` and `*.sub.domain.tld`, while preventing a trailing root dot from satisfying the “has another dot” requirement.

## Residual Risk

None

## Patch

`017-trailing-dot-wildcard-matches-top-level-domain.patch`

```diff
diff --git a/libtls/tls_verify.c b/libtls/tls_verify.c
index de95ab8..d441058 100644
--- a/libtls/tls_verify.c
+++ b/libtls/tls_verify.c
@@ -56,8 +56,8 @@ tls_match_name(const char *cert_name, const char *name)
 		if (cert_domain[1] == '.')
 			return -1;
 		next_dot = strchr(&cert_domain[1], '.');
-		/* Disallow "*.bar" */
-		if (next_dot == NULL)
+		/* Disallow "*.bar" and "*.bar." */
+		if (next_dot == NULL || next_dot[1] == '\0')
 			return -1;
 		/* Disallow "*.bar.." */
 		if (next_dot[1] == '.')
```