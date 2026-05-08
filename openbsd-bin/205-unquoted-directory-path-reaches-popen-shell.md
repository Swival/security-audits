# Unquoted Directory Path Reaches `popen` Shell

## Classification

Command execution, medium severity.

## Affected Locations

`usr.bin/mg/cscope.c:190`

## Summary

`cscreatelist()` builds a shell command with an unquoted user-supplied directory path and executes it with `popen()`. A valid directory name containing shell metacharacters can therefore cause shell command execution when the victim indexes that directory.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The victim accepts or enters an attacker-controlled directory path.

## Proof

`cscreatelist()` obtains the directory path through `eread()` into `dir`. It validates only that the path exists and is a directory with `stat(dir)` and `S_ISDIR`.

Shell metacharacters are valid in directory names, so a directory such as:

```sh
repo;touch mg_popen_pwned;#
```

passes the directory check.

The unsanitized value is then inserted into a shell command:

```c
snprintf(cmd, sizeof(cmd), "cscope-indexer -v %s", dir);
```

That command is executed by:

```c
popen(cmd, "r");
```

Because `popen()` invokes the shell, the resulting command is interpreted as:

```sh
cscope-indexer -v repo;touch mg_popen_pwned;#
```

A runtime proof of concept using the same `snprintf()` / `popen()` pattern and a fake `cscope-indexer` in `PATH` executed the injected `touch`, producing `pwned=yes`.

## Why This Is A Real Bug

The input is attacker-controlled under the stated precondition, and the existing validation confirms only filesystem type, not shell safety. Since shell metacharacters are allowed in directory names, a malicious path can simultaneously be a valid directory and a command injection payload. `popen()` executes through the shell, so the metacharacters are not passed as literal path characters.

The impact is command execution as the `mg` process user.

## Fix Requirement

The preferred fix is to execute `cscope-indexer` with an argument vector and avoid the shell entirely. If `popen()` must remain, the directory argument must be shell-quoted before interpolation into the command string.

## Patch Rationale

The patch shell-quotes `dir` before building the command string. It wraps the directory in single quotes and safely encodes embedded single quotes using the standard shell sequence:

```sh
'\'''
```

This causes shell metacharacters such as `;`, `#`, spaces, `$()`, backticks, and redirections to be treated as literal path characters rather than command syntax.

The patch also bounds-checks writes into `qdir` before appending quoted content, preserving the existing failure behavior when command construction would exceed fixed buffer sizes.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/mg/cscope.c b/usr.bin/mg/cscope.c
index 20140b7..16af60e 100644
--- a/usr.bin/mg/cscope.c
+++ b/usr.bin/mg/cscope.c
@@ -157,7 +157,9 @@ cscreatelist(int f, int n)
 	struct buffer *bp;
 	struct stat sb;
 	FILE *fpipe;
-	char dir[NFILEN], cmd[BUFSIZ], title[BUFSIZ], *line, *bufp;
+	char dir[NFILEN], qdir[NFILEN * 4 + 1], cmd[BUFSIZ], title[BUFSIZ];
+	char *line, *bufp, *q;
+	const char *d;
 	size_t sz;
 	ssize_t len;
 	int clen;
@@ -184,7 +186,28 @@ cscreatelist(int f, int n)
 	if (csexists("cscope-indexer") == FALSE)
 		return(dobeep_msg("no such file or directory, cscope-indexer"));
 
-	clen = snprintf(cmd, sizeof(cmd), "cscope-indexer -v %s", dir);
+	q = qdir;
+	*q++ = '\'';
+	for (d = dir; *d != '\0'; d++) {
+		if (*d == '\'') {
+			if ((size_t)(q - qdir) + 4 >= sizeof(qdir))
+				return (FALSE);
+			*q++ = '\'';
+			*q++ = '\\';
+			*q++ = '\'';
+			*q++ = '\'';
+		} else {
+			if ((size_t)(q - qdir) + 1 >= sizeof(qdir))
+				return (FALSE);
+			*q++ = *d;
+		}
+	}
+	if ((size_t)(q - qdir) + 1 >= sizeof(qdir))
+		return (FALSE);
+	*q++ = '\'';
+	*q = '\0';
+
+	clen = snprintf(cmd, sizeof(cmd), "cscope-indexer -v %s", qdir);
 	if (clen < 0 || clen >= sizeof(cmd))
 		return (FALSE);
```