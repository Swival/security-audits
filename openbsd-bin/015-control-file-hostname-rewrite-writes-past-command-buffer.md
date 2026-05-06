# control-file hostname rewrite writes past command buffer

## Classification

Out-of-bounds write; high severity; remotely triggerable by an authenticated/allowed lpd client.

## Affected Locations

`lpr/lpd/recvjob.c:168`

## Summary

`recvjob()` rewrites the host portion of a received control-file name with the authenticated peer hostname. The rewrite assumes the parsed filename is at least six bytes long and that `cp + 6` remains inside the global `line[BUFSIZ]` command buffer. A crafted control-file command can place `cp` within the final five bytes of `line`, making `cp + 6` point past the buffer and making the copy length underflow to a huge `size_t`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `lpd` accepts the client's host.
- The accepted client submits a print job.
- The submitted job includes a control-file command using service command `\2`.

## Proof

The reproduced trigger is:

- `lpd.c` accepts a TCP client, validates it with `chkhost()`, sets `from_remote = 1`, and dispatches service command `\2` to `recvjob()` for an allowed remote host.
- `lpr/lpd/recvjob.c` reads the remote command into global `line[BUFSIZ]`.
- The command reader accepts a newline at `line + sizeof(line) - 3` before reporting overflow.
- A command shaped as `\2` + `0` repeated `sizeof(line)-7` + ` cf\n` leaves the parsed size as `0` while placing the filename pointer at `line + sizeof(line) - 5`.
- The vulnerable call then evaluates `strlcpy(cp + 6, from, sizeof(line) + line - cp - 6)`.
- With `cp == line + sizeof(line) - 5`, the destination `cp + 6` is outside `line`, and the length expression is `-1`, converted to a huge `size_t`.

This corrupts receiver memory before later rejection paths such as `strchr()`, `chksize()`, or file-transfer validation can stop processing.

## Why This Is A Real Bug

The code performs pointer arithmetic on attacker-influenced `cp` without first proving that the expected six-byte control-file prefix exists inside `line`. Because `cp` can legally point near the end of the accepted command buffer, `cp + 6` can be outside the object. The computed remaining length can also underflow, turning a bounded copy into an out-of-bounds write primitive against the lpd receiver process.

## Fix Requirement

Reject malformed control-file names before rewriting the hostname:

- The filename must contain at least the six bytes required before the host portion.
- The authenticated hostname must fit in the remaining `line` buffer space after `cp + 6`.
- Rejection must happen before calling `strlcpy(cp + 6, ...)`.

## Patch Rationale

The patch adds a guard before the hostname rewrite:

```c
if (strlen(cp) < 6 ||
    strlen(from) >= sizeof(line) + line - cp - 6)
        frecverr("readjob: %s: illegal path name", cp);
```

This prevents both failure modes:

- `strlen(cp) < 6` rejects filenames where `cp + 6` would not refer to bytes within the parsed filename.
- `strlen(from) >= sizeof(line) + line - cp - 6` rejects rewrites where the authenticated hostname plus terminator would not fit in the remaining command buffer.

Only after those checks does the existing `strlcpy(cp + 6, from, ...)` execute.

## Residual Risk

None

## Patch

```diff
diff --git a/lpr/lpd/recvjob.c b/lpr/lpd/recvjob.c
index 787da15..feb1865 100644
--- a/lpr/lpd/recvjob.c
+++ b/lpr/lpd/recvjob.c
@@ -168,6 +168,9 @@ readjob(void)
 			 * something different than what gethostbyaddr()
 			 * returns
 			 */
+			if (strlen(cp) < 6 ||
+			    strlen(from) >= sizeof(line) + line - cp - 6)
+				frecverr("readjob: %s: illegal path name", cp);
 			strlcpy(cp + 6, from, sizeof(line) + line - cp - 6);
 			if (strchr(cp, '/'))
 				frecverr("readjob: %s: illegal path name", cp);
```