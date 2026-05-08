# Recursive SCP Download Accepts Unexpected Peer Filenames

## Classification

Policy bypass, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ssh/scp.c:1103`

## Summary

Legacy SCP recursive download trusts attacker-supplied top-level `C` and `D` records more broadly than the requested source path permits. In SCP mode, `tolocal()` runs remote `scp -f <src>` and calls `sink(1, destination, src)`, but `sink()` only builds requested-name patterns when `src != NULL && !iamrecursive && !Tflag`. Because recursive downloads set `iamrecursive`, top-level peer filename matching is skipped entirely.

An attacker-controlled SCP server can therefore return unexpected top-level names, including directories such as `.ssh`, and then send nested file records such as `authorized_keys`. The client cannot be forced outside the chosen local destination because `/`, `.`, and `..` are rejected, but arbitrary nested files beneath that destination can be created or overwritten.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

## Preconditions

User runs legacy SCP recursive download from an attacker-controlled server to a local directory.

## Proof

The reproduced vulnerable path is:

- `tolocal()` starts legacy SCP download with remote command `scp -f <src>` and calls `sink(1, argv + argc - 1, src)`.
- In `sink()`, requested-name patterns are prepared only under `src != NULL && !iamrecursive && !Tflag`.
- During recursive downloads, `iamrecursive` is true, so `npatterns` remains `0`.
- With `npatterns == 0`, the filename-match enforcement block is skipped.
- The remaining filename validation only rejects empty names, names containing `/`, `.` and `..`.
- A malicious server can send `D0700 0 .ssh\n`, then within the recursive sink send `C0600 <len> authorized_keys\n...`.
- The client creates/descends into the attacker-selected directory and opens the nested file with `open(np, O_WRONLY|O_CREAT, mode)`, then truncates it with `ftruncate()`.

Practical impact: if the user chooses `$HOME` as the local destination, the attacker can create or overwrite `$HOME/.ssh/authorized_keys`.

## Why This Is A Real Bug

The SCP client already contains peer filename matching for non-recursive downloads, showing that unexpected peer filenames are not intended to be accepted by default. Recursive downloads omit this enforcement at the top level even though the same trust boundary exists: the remote SCP peer controls protocol records and filenames.

The exploit is constrained but meaningful. The slash, `.` and `..` checks prevent path traversal outside the chosen destination, but they do not prevent attacker-chosen nested paths under that destination. Recursive `D` records provide the nesting needed to overwrite sensitive files beneath the destination directory.

## Fix Requirement

Enforce requested basename matching for recursive top-level records and reject unexpected top-level names unless `-T` disables strict filename checking.

Recursive child records must not be matched against the original top-level source basename, because nested entries are legitimate contents of the accepted directory.

## Patch Rationale

The patch removes the `!iamrecursive` condition when preparing requested-name patterns:

```diff
-if (src != NULL && !iamrecursive && !Tflag) {
+if (src != NULL && !Tflag) {
```

This makes recursive top-level downloads subject to the same requested-name validation as non-recursive downloads.

The patch also changes recursive descent from:

```diff
-sink(1, vect, src);
+sink(1, vect, NULL);
```

This prevents the original top-level source pattern from being incorrectly applied to legitimate entries inside an accepted directory. As a result, only the initial peer-provided top-level record must match the requested source basename; nested entries are handled by the existing filename safety checks.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/scp.c b/usr.bin/ssh/scp.c
index 2ec3d49..6da9d62 100644
--- a/usr.bin/ssh/scp.c
+++ b/usr.bin/ssh/scp.c
@@ -1652,7 +1652,7 @@ sink(int argc, char **argv, const char *src)
 	(void) atomicio(vwrite, remout, "", 1);
 	if (stat(targ, &stb) == 0 && S_ISDIR(stb.st_mode))
 		targisdir = 1;
-	if (src != NULL && !iamrecursive && !Tflag) {
+	if (src != NULL && !Tflag) {
 		/*
 		 * Prepare to try to restrict incoming filenames to match
 		 * the requested destination file glob.
@@ -1817,7 +1817,7 @@ sink(int argc, char **argv, const char *src)
 					goto bad;
 			}
 			vect[0] = xstrdup(np);
-			sink(1, vect, src);
+			sink(1, vect, NULL);
 			if (setimes) {
 				setimes = 0;
 				(void) utimes(vect[0], tv);
```