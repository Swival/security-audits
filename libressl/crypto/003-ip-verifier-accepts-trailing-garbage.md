# IP verifier accepts trailing garbage

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

x509/x509_utl.c:1169

## Summary

`X509_check_ip_asc()` accepts malformed IPv4 strings with trailing non-IP characters. The ASCII IP verifier parses `1.2.3.4.garbage` as the byte address `1.2.3.4`, then performs certificate IP SAN matching against that truncated value. This can make IP identity verification succeed for an address string that should be rejected.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller uses `X509_check_ip_asc()` for certificate IP identity verification.
- Attacker can influence or supply the ASCII IPv4 reference identifier passed to the verifier.
- Certificate contains an IP SAN matching the truncated IPv4 address.

## Proof

`X509_check_ip_asc()` converts the supplied string with `a2i_ipadd()` and only rejects conversion length `0`.

For inputs without `:`, `a2i_ipadd()` routes to IPv4 parsing:

```c
if (!ipv4_from_asc(ipout, ipasc))
	return 0;
return 4;
```

The vulnerable IPv4 parser used:

```c
if (sscanf(in, "%d.%d.%d.%d", &a0, &a1, &a2, &a3) != 4)
	return 0;
```

`sscanf("%d.%d.%d.%d")` successfully parses four integers from `1.2.3.4.garbage` and stops after the fourth octet. The parser then checks only that the parsed octets are within `0..255`, writes bytes `01 02 03 04`, and returns success.

`X509_check_ip_asc()` then calls `do_x509_check()` with `chklen == 4`. `do_x509_check()` compares the 4-byte value against `GEN_IPADD` OCTET STRING SANs using exact length and byte comparison, so a certificate containing IP SAN `1.2.3.4` is accepted for malformed input `1.2.3.4.garbage`.

## Why This Is A Real Bug

`X509_check_ip_asc()` is the certificate IP identity verification control. It must reject invalid ASCII IP reference identifiers, not normalize them by silently truncating unconsumed suffixes.

The behavior is deterministic:

- `1.2.3.4.garbage` is not a valid IPv4 address.
- The parser accepts it as `1.2.3.4`.
- The verifier compares the truncated bytes.
- A certificate valid for `1.2.3.4` is accepted for the malformed reference identifier.

This is a fail-open verification behavior in a security boundary.

## Fix Requirement

Require full consumption of the IPv4 input after the fourth octet. The parser must reject any trailing byte after a syntactically complete IPv4 address.

## Patch Rationale

The patch adds `%n` to the `sscanf()` format and checks that the recorded parse offset lands on the string terminator:

```c
if (sscanf(in, "%d.%d.%d.%d%n", &a0, &a1, &a2, &a3, &n) != 4 ||
    in[n] != '\0')
	return 0;
```

`%n` records how many characters were consumed after parsing the fourth octet. Requiring `in[n] == '\0'` preserves valid IPv4 parsing while rejecting trailing garbage such as `.garbage`, spaces, or other suffixes.

The existing octet range checks remain unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/x509/x509_utl.c b/x509/x509_utl.c
index 2e60834..197c5b9 100644
--- a/x509/x509_utl.c
+++ b/x509/x509_utl.c
@@ -1294,8 +1294,9 @@ LCRYPTO_ALIAS(a2i_ipadd);
 static int
 ipv4_from_asc(unsigned char *v4, const char *in)
 {
-	int a0, a1, a2, a3;
-	if (sscanf(in, "%d.%d.%d.%d", &a0, &a1, &a2, &a3) != 4)
+	int a0, a1, a2, a3, n;
+	if (sscanf(in, "%d.%d.%d.%d%n", &a0, &a1, &a2, &a3, &n) != 4 ||
+	    in[n] != '\0')
 		return 0;
 	if ((a0 < 0) || (a0 > 255) || (a1 < 0) || (a1 > 255) ||
 	    (a2 < 0) || (a2 > 255) || (a3 < 0) || (a3 > 255))
```