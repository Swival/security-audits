# MDTM success reply scans past string terminator

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/ftp/util.c:629`

## Summary

`remotemodtime()` parses the server-controlled `reply_string` after a successful `MDTM` command. It scans for the first whitespace byte with `while (!isspace((unsigned char)*timestr)) timestr++;` but does not stop at `'\0'`. A malicious FTP server can return a successful MDTM reply with no whitespace, causing the client to read past the string terminator and potentially crash.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The client requests MDTM metadata from an attacker-controlled FTP server.
- The attacker-controlled server returns a successful `2xx` MDTM reply whose stored first line contains no whitespace, such as `213\r\n` or `213xxx\r\n`.

## Proof

`remotemodtime()` sends `command("MDTM %s", file)` and parses `reply_string` whenever `command()` returns `COMPLETE`.

`command()` delegates to `getreply()`, which stores the first server reply line in `reply_string` without validating MDTM response syntax. Therefore, an attacker-controlled successful reply can reach the MDTM parser.

The vulnerable parser initializes:

```c
char *timestr = reply_string;
```

It then scans for whitespace:

```c
while (!isspace((unsigned char)*timestr))
	timestr++;
```

For a reply line with no whitespace, `*timestr` eventually becomes `'\0'`. Since `isspace('\0')` is false, the loop increments past the terminator and continues dereferencing bytes outside the string. This occurs before the later `sscanf()` parsing.

Reachable client actions include `modtime`, `newer`, and retrieval flows that preserve timestamps.

## Why This Is A Real Bug

The input is fully controlled by the FTP server after the client issues `MDTM`. FTP clients commonly connect to untrusted remote servers. The code trusts only the FTP reply class, not the MDTM reply grammar, before performing an unbounded scan. A syntactically malformed but successful response can therefore trigger an out-of-bounds read in the client process, causing denial of service.

## Fix Requirement

The parser must stop scanning at `'\0'` and reject malformed successful MDTM replies that do not contain both a separator and a timestamp. It must also reject replies where timestamp field parsing fails.

## Patch Rationale

The patch bounds the first scan by adding an explicit `*timestr != '\0'` condition. It then rejects malformed replies if the separator scan reaches the terminator or if only whitespace remains. Finally, it checks that `sscanf()` successfully parsed all six required timestamp fields before using the parsed values.

This preserves valid MDTM behavior while treating malformed successful replies as invalid metadata instead of continuing into unsafe parsing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ftp/util.c b/usr.bin/ftp/util.c
index 91c689b..4b97dec 100644
--- a/usr.bin/ftp/util.c
+++ b/usr.bin/ftp/util.c
@@ -628,10 +628,14 @@ remotemodtime(const char *file, int noisy)
 		char *timestr = reply_string;
 
 		/* Repair `19%02d' bug on server side */
-		while (!isspace((unsigned char)*timestr))
+		while (*timestr != '\0' && !isspace((unsigned char)*timestr))
 			timestr++;
+		if (*timestr == '\0')
+			goto invalid;
 		while (isspace((unsigned char)*timestr))
 			timestr++;
+		if (*timestr == '\0')
+			goto invalid;
 		if (strncmp(timestr, "191", 3) == 0) {
 			fprintf(ttyout,
 	    "Y2K warning! Fixed incorrect time-val received from server.\n");
@@ -639,8 +643,9 @@ remotemodtime(const char *file, int noisy)
 			timestr[1] = '2';
 			timestr[2] = '0';
 		}
-		sscanf(reply_string, "%*s %04d%02d%02d%02d%02d%02d", &yy, &mo,
-			&day, &hour, &min, &sec);
+		if (sscanf(reply_string, "%*s %04d%02d%02d%02d%02d%02d", &yy, &mo,
+			&day, &hour, &min, &sec) != 6)
+			goto invalid;
 		memset(&timebuf, 0, sizeof(timebuf));
 		timebuf.tm_sec = sec;
 		timebuf.tm_min = min;
@@ -666,6 +671,7 @@ remotemodtime(const char *file, int noisy)
 		fputs(reply_string, ttyout);
 		fputc('\n', ttyout);
 	}
+invalid:
 	verbose = overbose;
 	if (rtime == -1)
 		code = ocode;
```