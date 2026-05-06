# Unbounded LMTP Reply Line Allocation

## Classification
Denial of service, medium severity. Confidence: certain.

## Affected Locations
`smtpd/mail.lmtp.c:249`

## Summary
`lmtp_engine()` reads LMTP server replies with `getline()` before applying any syntax or length validation. An attacker-controlled LMTP destination can send an overlong response line without a newline, causing repeated heap growth and potential memory exhaustion in the mail delivery process.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
`mail.lmtp` connects to an attacker-controlled LMTP destination.

## Proof
After `lmtp_connect()` returns, `lmtp_engine()` immediately reads the LMTP banner and later replies from the connected peer.

The vulnerable code uses:

```c
getline(&line, &linesize, file_read)
```

Because `getline()` has no caller-specified maximum, a malicious LMTP server can send a response such as:

```text
220 <arbitrarily long byte stream without '\n'>
```

`getline()` continues reallocating `line` until it receives a newline, reaches EOF, fails allocation, or the process is killed. The later checks for LMTP syntax and status code only execute after the full line has already been allocated, so they do not limit memory consumption.

The reproducer confirmed this path is reachable immediately on banner read and that no LMTP reply length cap exists in the affected code.

## Why This Is A Real Bug
The attacker controls bytes read by `getline()` from the LMTP peer. The program trusts that peer to provide newline-terminated, reasonably sized replies, but enforces no maximum before allocation. Session lifetime or concurrency limits do not prevent memory exhaustion during a single oversized read.

This allows an attacker-controlled LMTP backend to trigger delivery-process resource exhaustion.

## Fix Requirement
LMTP reply reads must enforce a fixed maximum line length and abort the session when that limit is exceeded.

## Patch Rationale
The patch replaces dynamic `getline()` allocation in `lmtp_engine()` with a fixed-size stack buffer:

```c
#define LMTP_LINE_MAX 512
char line[LMTP_LINE_MAX + 1];
```

It reads replies using `fgets()` with the bounded buffer size, then rejects any line that fills the buffer without a newline:

```c
if (linelen == LMTP_LINE_MAX && line[linelen - 1] != '\n')
	errx(EX_TEMPFAIL, "LMTP server sent a line that is too long");
```

This prevents unbounded allocation before LMTP validation while preserving the existing newline stripping, syntax checks, status handling, and phase logic.

## Residual Risk
None

## Patch
`012-unbounded-lmtp-reply-line-allocation.patch`

```diff
diff --git a/smtpd/mail.lmtp.c b/smtpd/mail.lmtp.c
index dc46d12..688ac81 100644
--- a/smtpd/mail.lmtp.c
+++ b/smtpd/mail.lmtp.c
@@ -27,6 +27,8 @@
 #include <sysexits.h>
 #include <unistd.h>
 
+#define LMTP_LINE_MAX	512
+
 enum phase {
 	PHASE_BANNER,
 	PHASE_HELO,
@@ -228,9 +230,8 @@ lmtp_engine(int fd_read, struct session *session)
 	int fd_write = 0;
 	FILE *file_read = 0;
 	FILE *file_write = 0;
-	char *line = NULL;
-	size_t linesize = 0;
-	ssize_t linelen;
+	char line[LMTP_LINE_MAX + 1];
+	size_t linelen;
 	enum phase phase = PHASE_BANNER;
 
 	if ((fd_write = dup(fd_read)) == -1)
@@ -245,12 +246,15 @@ lmtp_engine(int fd_read, struct session *session)
 	do {
 		fflush(file_write);
 
-		if ((linelen = getline(&line, &linesize, file_read)) == -1) {
+		if (fgets(line, sizeof line, file_read) == NULL) {
 			if (ferror(file_read))
-				err(EX_TEMPFAIL, "getline");
+				err(EX_TEMPFAIL, "fgets");
 			else
 				errx(EX_TEMPFAIL, "unexpected EOF from LMTP server");
 		}
+		linelen = strlen(line);
+		if (linelen == LMTP_LINE_MAX && line[linelen - 1] != '\n')
+			errx(EX_TEMPFAIL, "LMTP server sent a line that is too long");
 		line[strcspn(line, "\n")] = '\0';
 		line[strcspn(line, "\r")] = '\0';
```