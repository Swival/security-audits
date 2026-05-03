# Multipart Boundary Accepts Prefixed Delimiter Lines

## Classification

Policy bypass, medium severity.

## Affected Locations

`asn1/asn_mime.c:975`

## Summary

`SMIME_read_ASN1` accepts `multipart/signed` input and passes the attacker-controlled `boundary` parameter to `multi_split`. `multi_split` relies on `mime_bound_check` to identify MIME part delimiters.

Before the patch, `mime_bound_check` only required a line to start with `--` followed by the configured boundary token. If the following two bytes were not `--`, it returned a normal part boundary without validating that the boundary token had actually ended.

As a result, a malformed delimiter such as `--BOUNDARYevil` was accepted as `--BOUNDARY`, allowing OpenSSL to split S/MIME parts differently than strict MIME parsers.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A recipient parses attacker-supplied `multipart/signed` S/MIME input with `SMIME_read_ASN1`.
- The message uses a boundary parameter controlled by the sender.
- The attacker places extra non-delimiter bytes immediately after the boundary token on a would-be delimiter line.

## Proof

The vulnerable logic in `mime_bound_check` accepted any line matching this prefix shape:

```text
--<boundary>
```

It only distinguished a final delimiter by checking whether the next two bytes were `--`. Otherwise, it returned `1` for a normal part boundary.

Representative trigger:

```text
Content-Type: multipart/signed; boundary="B"

--B
Content-Type: text/plain

signed-prefix
--Bevil
Content-Type: application/pkcs7-signature

<base64 signature over only signed-prefix>
--B--
```

OpenSSL treats `--Bevil` as the second-part delimiter for boundary `B`. A strict MIME parser treats `--Bevil` as body text because the delimiter does not terminate after `B`.

This creates an S/MIME parsing discrepancy where OpenSSL verifies or parses a different signed content/signature split than a conforming MIME consumer would render or process.

## Why This Is A Real Bug

MIME boundary delimiter recognition must not accept arbitrary bytes immediately after the boundary token. A valid delimiter line must end after the boundary token, optionally with legal linear whitespace, line ending, or, for the closing delimiter, `--`.

The previous implementation accepted prefixed delimiter lines such as:

```text
--BOUNDARYevil
```

for:

```text
boundary="BOUNDARY"
```

That behavior permits multipart part-smuggling and authentication desynchronization: OpenSSL can treat attacker-controlled body text as a delimiter while another MIME parser treats the same bytes as signed content.

## Fix Requirement

Require a matched boundary token to be followed only by:

- CRLF or LF line ending
- NUL terminator
- legal linear whitespace before the line ending or NUL
- `--` closing delimiter, followed only by legal linear whitespace, line ending, or NUL

Reject delimiter candidates containing any other byte after the boundary token.

## Patch Rationale

The patch advances the pointer past `--<boundary>` and validates the suffix before returning a boundary match.

For closing delimiters, it accepts:

```text
--<boundary>--
--<boundary>--<LWSP>
--<boundary>--<LWSP><EOL>
```

and rejects closing candidates with other trailing bytes.

For normal part delimiters, it accepts:

```text
--<boundary>
--<boundary><LWSP>
--<boundary><LWSP><EOL>
```

and rejects prefixed strings such as:

```text
--BOUNDARYevil
```

This aligns `mime_bound_check` with strict MIME delimiter semantics and prevents OpenSSL from splitting malformed multipart input differently from conforming parsers.

## Residual Risk

None

## Patch

```diff
diff --git a/asn1/asn_mime.c b/asn1/asn_mime.c
index d42dd86..dbafa1b 100644
--- a/asn1/asn_mime.c
+++ b/asn1/asn_mime.c
@@ -985,9 +985,18 @@ mime_bound_check(char *line, int linelen, char *bound, int blen)
 		return 0;
 	/* Check for part boundary */
 	if (!strncmp(line, "--", 2) && !strncmp(line + 2, bound, blen)) {
-		if (!strncmp(line + blen + 2, "--", 2))
-			return 2;
-		else
+		line += blen + 2;
+		if (!strncmp(line, "--", 2)) {
+			line += 2;
+			while (*line == ' ' || *line == '\t')
+				line++;
+			if (*line == '\r' || *line == '\n' || *line == '\0')
+				return 2;
+			return 0;
+		}
+		while (*line == ' ' || *line == '\t')
+			line++;
+		if (*line == '\r' || *line == '\n' || *line == '\0')
 			return 1;
 	}
 	return 0;
```