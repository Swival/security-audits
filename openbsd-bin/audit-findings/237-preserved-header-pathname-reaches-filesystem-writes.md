# Preserved Header Pathname Reaches Filesystem Writes

## Classification

Path traversal. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/uudecode/uudecode.c:265`

## Summary

When `uudecode -s` decodes attacker-supplied input, the filename from the `begin` or `begin-base64` header is preserved and used as the output path. Before the patch, absolute paths and parent-directory components were not rejected, allowing decoded attacker-controlled bytes to create or replace arbitrary writable files as the victim user.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

Victim runs `uudecode -s` on attacker-supplied uuencoded or base64-encoded input.

## Proof

`decode2()` parses the header filename into `q` from the `begin` line at `usr.bin/uudecode/uudecode.c:197`.

With `sflag` set, the slash-stripping branch is skipped at `usr.bin/uudecode/uudecode.c:230` and `usr.bin/uudecode/uudecode.c:255`. If `-o` is not used, `outfile` is assigned directly from the preserved header filename.

That path then reaches filesystem operations:

- `lstat(outfile, &st)` at `usr.bin/uudecode/uudecode.c:269`
- possible `unlink(outfile)` at `usr.bin/uudecode/uudecode.c:278`
- `open(outfile, O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW, mode)` at `usr.bin/uudecode/uudecode.c:298`
- decoded bytes are written through `uu_decode()` or `base64_decode()` at `usr.bin/uudecode/uudecode.c:305`

A malicious input such as:

```text
begin-base64 644 ../victim-path
```

causes decoded bytes to be written to `../victim-path` relative to the victim’s current directory. Absolute paths are likewise honored if writable by the victim.

## Why This Is A Real Bug

The `-s` option preserves header pathnames, but preservation did not imply authorization to traverse outside the intended working location. Header filenames are attacker-controlled input, and the existing write path could create new files or replace existing regular writable files when `-i` is not used.

The existing symlink protections do not prevent traversal through absolute paths or `..` components. `O_NOFOLLOW` only affects the final path component, and `lstat()`/`unlink()` still operate on the attacker-selected pathname.

## Fix Requirement

Reject preserved header filenames that are absolute paths or contain parent-directory traversal components before assigning them to `outfile` and before any filesystem operation occurs.

## Patch Rationale

The patch adds validation only when both conditions hold:

- `-o` is not used, so the output path comes from the input header.
- `sflag` is set, so the header pathname is preserved instead of stripped to a leaf name.

The new checks reject:

- absolute paths beginning with `/`
- exact `..`
- leading `../`
- embedded `/../`
- trailing `/..`

This blocks traversal while preserving normal `-s` behavior for relative non-traversing pathnames and preserving explicit `-o` behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/uudecode/uudecode.c b/usr.bin/uudecode/uudecode.c
index 22c8d01..6af1a72 100644
--- a/usr.bin/uudecode/uudecode.c
+++ b/usr.bin/uudecode/uudecode.c
@@ -258,8 +258,19 @@ decode2(void)
 		if (p != NULL)
 			q = p + 1;
 	}
-	if (!oflag)
+	if (!oflag) {
+		if (sflag) {
+			n = strlen(q);
+			if (*q == '/' || strcmp(q, "..") == 0 ||
+			    strncmp(q, "../", 3) == 0 ||
+			    strstr(q, "/../") != NULL ||
+			    (n > 2 && strcmp(q + n - 3, "/..") == 0)) {
+				warnx("%s: bad output filename", infile);
+				return (1);
+			}
+		}
 		outfile = q;
+	}
 
 	/* POSIX says "/dev/stdout" is a 'magic cookie' not a special file. */
 	if (pflag || strcmp(outfile, "/dev/stdout") == 0)
```