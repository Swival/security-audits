# Print Job Fields Inject Mail Recipients

## Classification

Injection, low severity, confirmed with certainty.

## Affected Locations

`lpr/lpd/printjob.c:756`

## Summary

LPD print job control-file fields `M` and `H` can inject additional mail recipients into job notification email headers. When notification is enabled, attacker-controlled values are written into a `To:` header and passed to `sendmail -t`, which parses comma-delimited header recipients as envelope recipients.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The daemon processes a submitted print job.
- Mail notification is enabled through an `M` control-file field.
- The submitted control file contains attacker-controlled `M` and/or `H` values.

## Proof

`recvjob` preserves submitted control-file contents in the spool and only rewrites the control-file name host suffix, not the internal `H` or `M` fields.

`printit()` reads the attacker-controlled `H` field into `fromhost` and later processes attacker-controlled `M` lines in pass 2.

`sendmail()` previously rejected only `M` values whose first byte was `-`, `/`, or non-printable. It did not reject commas, `@`, or unsafe characters in `fromhost`.

The function then executes sendmail with `-t` and writes:

```c
printf("To: %s@%s\n", user, fromhost);
```

A crafted control file such as:

```text
Hclient.example,victim@example.net
Mdaemon
```

produces:

```text
To: daemon@client.example,victim@example.net
```

Because `sendmail -t` derives recipients from message headers, `victim@example.net` is parsed as an additional recipient controlled by the job submitter.

## Why This Is A Real Bug

The affected values are attacker-controlled print job fields. They are inserted directly into an RFC-style mail recipient header without constraining them to a single mailbox-safe atom. Commas in `M` or `H` are therefore interpreted by `sendmail -t` as recipient separators, causing notification mail to be sent to attacker-chosen third-party addresses.

This is not only display corruption: `sendmail -t` uses the generated `To:` header to determine envelope recipients.

## Fix Requirement

Validate both `M` and `H` as single mailbox-safe atoms before writing mail headers. Reject empty values and any character that can terminate, separate, or otherwise alter the recipient address syntax.

## Patch Rationale

The patch adds strict validation in `sendmail()` before invoking sendmail:

- Rejects empty `user`.
- Preserves rejection of leading `-` and `/`.
- Rejects empty `fromhost`.
- Allows only `A-Z`, `a-z`, `0-9`, `_`, `-`, and `.` in `user`.
- Allows only `A-Z`, `a-z`, `0-9`, `-`, and `.` in `fromhost`.

This blocks commas, whitespace, `@`, control characters, and other mail-header syntax characters from both attacker-controlled fields before the `To:` header is emitted.

## Residual Risk

None

## Patch

```diff
diff --git a/lpr/lpd/printjob.c b/lpr/lpd/printjob.c
index 9b8579e..b214165 100644
--- a/lpr/lpd/printjob.c
+++ b/lpr/lpd/printjob.c
@@ -1116,8 +1116,17 @@ sendmail(char *user, int bombed)
 	struct stat stb;
 	FILE *fp;
 
-	if (user[0] == '-' || user[0] == '/' || !isprint((unsigned char)user[0]))
+	if (user[0] == '\0' || user[0] == '-' || user[0] == '/' ||
+	    fromhost[0] == '\0')
 		return;
+	for (cp = user; *cp != '\0'; cp++)
+		if (!isalnum((unsigned char)*cp) && *cp != '_' &&
+		    *cp != '-' && *cp != '.')
+			return;
+	for (cp = fromhost; *cp != '\0'; cp++)
+		if (!isalnum((unsigned char)*cp) && *cp != '-' &&
+		    *cp != '.')
+			return;
 	pipe(p);
 	if ((s = dofork(DORETURN)) == 0) {		/* child */
 		dup2(p[0], 0);
```