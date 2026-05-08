# Newline Filenames Forge Dired Entries

## Classification

Path traversal / UI record injection.

Severity: medium.

Confidence: certain.

## Affected Locations

`usr.bin/mg/dired.c:631`

## Summary

`mg` dired builds its buffer from newline-delimited `ls -al` output and later treats each rendered line as a trusted file operation record. Because `ls` can emit raw newline bytes in filenames when stdout is a pipe, an attacker-controlled filename can inject a forged dired row. If a victim marks and expunges that forged row, `mg` deletes the sibling path named in the injected record with the victim's privileges.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A victim opens an attacker-writable directory in `mg` dired.
- The attacker can create filenames in that directory.
- The victim marks and expunges the forged dired entry.
- A target sibling path named in the forged record exists and is unlinkable by the victim.

## Proof

`dired_()` populates the dired buffer by invoking:

```c
d_exec(2, bp, NULL, "ls", "-al", dname, NULL)
```

`d_exec()` reads command output with `fgets()`, strips the trailing newline, and inserts each resulting line into the buffer with `addlinef()`.

OpenBSD `ls` emits filenames raw when stdout is not a terminal: `bin/ls/ls.c:112` only enables nonprint escaping for terminals, while `bin/ls/print.c:124` prints `p->fts_name` through `mbsprint`. Therefore a filename such as:

```text
aaa
-rw-r--r-- 1 root wheel 0 Jan  1 00:00 victim
```

is rendered as two dired records. The forged second line contains enough space-delimited fields for `d_warpdot()` to treat `victim` as the filename. `d_makename()` concatenates that parsed filename with `curbp->b_fname`, and `d_expunge()` calls `unlink()` on the resulting sibling path.

In a shared sticky directory such as `/tmp`, a lower-privileged attacker cannot directly unlink another user's or root-owned sibling file, but can create the newline-containing filename. If that victim opens the directory in dired and expunges the forged row, `mg` performs the unlink using the victim's privileges.

## Why This Is A Real Bug

The dired buffer conflates display output with an operation authority source. A filename byte sequence containing `\n` is valid on Unix filesystems, but `d_exec()` splits `ls` output on newlines and `d_warpdot()` accepts any line with sufficient fields as actionable. This lets attacker-controlled filename data cross a record boundary and become an independent delete target.

The impact is not cosmetic: the forged entry is consumed by `d_expunge()`, which performs `unlink()` or `rmdir()` on the parsed path.

## Fix Requirement

Dired must not allow newline bytes in filenames to create separate actionable records. The listing source must either reject such entries or escape newline/control characters before buffer insertion.

## Patch Rationale

The patch changes dired listing generation from `ls -al` to `ls -alq`:

```diff
-	if ((d_exec(2, bp, NULL, "ls", "-al", dname, NULL)) != TRUE)
+	if ((d_exec(2, bp, NULL, "ls", "-alq", dname, NULL)) != TRUE)
```

`ls -q` replaces non-printable characters with `?`, including newline bytes, so a newline embedded in a filename is rendered inside a single listing line instead of splitting the dired buffer into multiple records. This preserves the existing dired parsing model while preventing forged newline-delimited entries from being created. Note: OpenBSD's `ls` does not support `-B`; `-q` is the correct OpenBSD flag for this purpose.

## Residual Risk

Filenames containing non-printable characters will display with `?` substitutions. Expunging such entries will attempt to unlink the displayed name (with `?`), which will fail harmlessly since the actual filename differs. This is acceptable since the alternative (trusting raw filenames) is a security vulnerability.

## Patch

`105-newline-filenames-forge-dired-entries.patch`

```diff
diff --git a/usr.bin/mg/dired.c b/usr.bin/mg/dired.c
index a7d9372..b4761cf 100644
--- a/usr.bin/mg/dired.c
+++ b/usr.bin/mg/dired.c
@@ -967,7 +967,7 @@ dired_(char *dname)
 	bp = bfind(dname, TRUE);
 	bp->b_flag |= BFREADONLY | BFIGNDIRTY;
 
-	if ((d_exec(2, bp, NULL, "ls", "-al", dname, NULL)) != TRUE)
+	if ((d_exec(2, bp, NULL, "ls", "-alq", dname, NULL)) != TRUE)
 		return (NULL);
 
 	/* Find the line with ".." on it. */
```