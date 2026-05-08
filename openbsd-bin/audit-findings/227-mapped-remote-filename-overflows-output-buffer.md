# Mapped Remote Filename Overflows Output Buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.bin/ftp/small.c:687`

## Summary

`mget` can pass attacker-controlled remote filenames into `domap()` when filename mapping is enabled. `domap()` builds the mapped local filename in a static `new[PATH_MAX]` buffer, but the original implementation appended `$0`, token expansions, escaped literals, and ordinary literals without checking remaining capacity. A malicious FTP server can provide a long remote filename that causes `domap()` to write past `new`, corrupting ftp client memory before `recvrequest()` is called.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

User runs `mget` with filename mapping enabled.

## Proof

`mget()` obtains remote filenames from `remglob()` and passes each selected name as `xargv[1]` to `getit()`.

For an omitted local filename, `getit()` sets `argv[2] = argv[1]`, then applies filename mapping when `loc && mapflag`:

`usr.bin/ftp/small.c:214`

`usr.bin/ftp/small.c:258`

`usr.bin/ftp/small.c:288`

The remote filename is server-controlled through directory listing/globbing. The reproduced path showed `remglob()` reading lines into `buf[PATH_MAX]` with `fgets()` at `usr.bin/ftp/util.c:417` and `usr.bin/ftp/util.c:443`. A long no-slash filename passes the relative-path guard because `fileindir()` accepts parent `"."` at `usr.bin/ftp/util.c:687`.

`domap()` then writes mapped output into static storage:

`usr.bin/ftp/small.c:560`

In the vulnerable code, `$0` expansion copies the full input name without bounds checks:

```c
while (*cp3) {
	*cp1++ = *cp3++;
}
```

The same unbounded append pattern is used for token copies, escaped literals, literal alternatives, and the final terminator at `usr.bin/ftp/small.c:691` and `usr.bin/ftp/small.c:715`.

A small ASan harness using the committed `domap()` logic with a `PATH_MAX - 1` input name and `mapout="$0x"` produced a global-buffer-overflow immediately after `domap.new`.

## Why This Is A Real Bug

The attacker controls the remote filename supplied to `mget`. With `mapflag` enabled and a mapping such as `$0x`, `domap()` first copies up to `PATH_MAX - 1` bytes from the remote filename and then appends one more mapped byte plus a NUL terminator. Because `new` is only `PATH_MAX` bytes, the append or terminator crosses the static buffer boundary.

The overflow occurs before the transfer request, so no successful file download is required. The reproduced ASan global-buffer-overflow confirms the memory write beyond `domap.new`.

## Fix Requirement

All writes to `domap()` output buffer `new[PATH_MAX]` must be bounded. If the mapped filename cannot fit, mapping must fail safely without writing beyond `new`.

## Patch Rationale

The patch introduces an `APPEND(c)` helper inside `domap()` that checks `cp1 >= new + sizeof(new) - 1` before every byte append. On overflow, it prints `nmap: mapped filename too long.` and returns the original `name`, preserving space for the final NUL terminator.

The patch replaces all mapped-output writes through `*cp1++ = ...` with `APPEND(...)`, covering:

- escaped literals
- `$0` full-name expansion
- `$1` through `$9` token expansion
- bracket alternative literals
- default literal output

The final `*cp1 = '\0'` remains safe because `APPEND()` always leaves one byte available for the terminator.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ftp/small.c b/usr.bin/ftp/small.c
index 484d78f..83b9929 100644
--- a/usr.bin/ftp/small.c
+++ b/usr.bin/ftp/small.c
@@ -562,6 +562,14 @@ domap(char *name)
 	char *tp[9], *te[9];
 	int i, toks[9], toknum = 0, match = 1;
 
+#define APPEND(c) do { \
+	if (cp1 >= new + sizeof(new) - 1) { \
+		fputs("nmap: mapped filename too long.\n", ttyout); \
+		return (name); \
+	} \
+	*cp1++ = (c); \
+} while (0)
+
 	for (i=0; i < 9; ++i) {
 		toks[i] = 0;
 	}
@@ -610,7 +618,7 @@ domap(char *name)
 		switch (*cp2) {
 			case '\\':
 				if (*(cp2 + 1)) {
-					*cp1++ = *++cp2;
+					APPEND(*++cp2);
 				}
 				break;
 			case '[':
@@ -620,14 +628,14 @@ LOOP:
 						char *cp3 = name;
 
 						while (*cp3) {
-							*cp1++ = *cp3++;
+							APPEND(*cp3++);
 						}
 						match = 1;
 					} else if (toks[toknum = *cp2 - '1']) {
 						char *cp3 = tp[toknum];
 
 						while (cp3 != te[toknum]) {
-							*cp1++ = *cp3++;
+							APPEND(*cp3++);
 						}
 						match = 1;
 					}
@@ -642,7 +650,7 @@ LOOP:
 							   char *cp3 = name;
 
 							   while (*cp3) {
-								*cp1++ = *cp3++;
+								APPEND(*cp3++);
 							   }
 							} else if (toks[toknum =
 							    *cp2 - '1']) {
@@ -650,11 +658,11 @@ LOOP:
 
 								while (cp3 !=
 								    te[toknum]) {
-									*cp1++ = *cp3++;
+									APPEND(*cp3++);
 								}
 							}
 						} else if (*cp2) {
-							*cp1++ = *cp2++;
+							APPEND(*cp2++);
 						}
 					}
 					if (!*cp2) {
@@ -694,25 +702,26 @@ LOOP:
 						char *cp3 = name;
 
 						while (*cp3) {
-							*cp1++ = *cp3++;
+							APPEND(*cp3++);
 						}
 					} else if (toks[toknum = *cp2 - '1']) {
 						char *cp3 = tp[toknum];
 
 						while (cp3 != te[toknum]) {
-							*cp1++ = *cp3++;
+							APPEND(*cp3++);
 						}
 					}
 					break;
 				}
 				/* FALLTHROUGH */
 			default:
-				*cp1++ = *cp2;
+				APPEND(*cp2);
 				break;
 		}
 		cp2++;
 	}
 	*cp1 = '\0';
+#undef APPEND
 	if (!*new) {
 		return (name);
 	}
```