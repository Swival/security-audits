# raw RFC1413 ident permits transfer-log injection

## Classification

Log injection, medium severity, certain confidence.

## Affected Locations

`src/xferlog.c:126`

## Summary

`xferlog_write()` writes the RFC1413 ident value from `session.notes["mod_ident.rfc1413-ident"]` directly into the TransferLog line. The filename field is already normalized by replacing whitespace and control characters with underscores, but the ident field was not. A malicious client controlling its RFC1413 ident response can include carriage returns, newlines, or other control characters that make the single-line TransferLog record appear as forged log content.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The server uses RFC1413 ident.
- `TransferLog` is enabled.
- The attacker controls or influences the FTP client’s ident service response.

## Proof

The reproduced data flow is:

- `d_ident.c:220` queries the client’s ident service.
- `modules/mod_ident.c:237` reads one ident response line.
- `modules/mod_ident.c:268` parses the `USERID` response.
- `modules/mod_ident.c:240` strips only the response line ending.
- `modules/mod_ident.c:277` strips only trailing space or tab from the user-id field.
- Internal control characters such as `\r` can remain in the parsed ident.
- `modules/mod_ident.c:384` stores the ident in session notes.
- `src/xferlog.c:90` retrieves `mod_ident.rfc1413-ident`.
- `src/xferlog.c:84` sanitizes only `fname` into `fbuf`.
- `src/xferlog.c:113` formats the raw ident with `%s`.
- `src/xferlog.c:134` writes the resulting buffer to the transfer log.

A malicious ident response such as:

```text
USERID : UNIX : id\rThu Jan  1 00:00:00 1970 ... ftp 0 *
```

causes raw carriage-return log content to be written into a TransferLog entry. Log viewers or universal-newline parsers may display or consume the injected content as forged transfer-log data.

## Why This Is A Real Bug

`doc/howto/Logging.html:80` defines `TransferLog` as single-line, space-delimited entries. Allowing attacker-controlled RFC1413 ident data to contain whitespace or control characters violates that format.

The vulnerable code already recognizes this class of problem for filenames by mapping whitespace and control characters to underscores before formatting the log line. The same protection was missing for `rfc1413_ident`, even though it is inserted into the same space-delimited log record.

Because the ident value is written with `write(xferlogfd, buf, len)` after direct `%s` formatting, embedded control characters are preserved in the log output.

## Fix Requirement

Escape or normalize whitespace and control characters in `rfc1413_ident` before it is formatted into the TransferLog record.

## Patch Rationale

The patch adds an `ibuf` buffer and applies the same normalization policy used for filenames:

- Replace whitespace characters with `_`.
- Replace control characters with `_`.
- Preserve ordinary printable, non-whitespace ident characters.
- Continue mapping the exact `UNKNOWN` ident value to `*`.
- Continue using `*` when no authenticated ident is available.

This keeps TransferLog entries single-line and space-delimited while preserving benign ident content.

## Residual Risk

None

## Patch

```diff
diff --git a/src/xferlog.c b/src/xferlog.c
index ebc147be2..cbc69150c 100644
--- a/src/xferlog.c
+++ b/src/xferlog.c
@@ -70,7 +70,8 @@ int xferlog_write(long xfertime, const char *remhost, off_t fsize,
     const char *user, char abort_flag, const char *action_flags) {
   pool *tmp_pool;
   const char *rfc1413_ident = NULL, *xfer_proto;
-  char buf[LOGBUFFER_SIZE] = {'\0'}, fbuf[LOGBUFFER_SIZE] = {'\0'};
+  char buf[LOGBUFFER_SIZE] = {'\0'}, fbuf[LOGBUFFER_SIZE] = {'\0'},
+    ibuf[LOGBUFFER_SIZE] = {'\0'};
   int have_ident = FALSE, len;
   register unsigned int i = 0;
 
@@ -106,6 +107,13 @@ int xferlog_write(long xfertime, const char *remhost, off_t fsize,
     rfc1413_ident = "*";
   }
 
+  for (i = 0; (i + 1 < sizeof(ibuf)) && rfc1413_ident[i] != '\0'; i++) {
+    ibuf[i] = (PR_ISSPACE(rfc1413_ident[i]) || PR_ISCNTRL(rfc1413_ident[i])) ? '_' :
+      rfc1413_ident[i];
+  }
+  ibuf[i] = '\0';
+  rfc1413_ident = ibuf;
+
   xfer_proto = pr_session_get_protocol(0);
   tmp_pool = make_sub_pool(session.pool);
   pr_pool_tag(tmp_pool, "TransferLog message pool");
```