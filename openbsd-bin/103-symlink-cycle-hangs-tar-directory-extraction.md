# symlink cycle hangs tar directory extraction

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`bin/pax/file_subs.c:386`

## Summary

In tar extraction mode with `-L`, `node_creat()` follows symlinks while creating directory entries. The loop has no traversal limit or cycle detection, so an attacker-controlled archive can create a self-referential symlink and then a directory entry at the same path. Extraction then loops indefinitely before reaching `mkdir()`, denying service to the extractor.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Extractor runs tar mode with `-L`.
- Archive contents are attacker-controlled.
- Archive can order entries so a symlink is created before a directory entry at the same path.

## Proof

A malicious archive can contain:

```text
a -> a
a/
```

Execution path:

- The symlink entry `a -> a` is accepted because relative symlinks without `..` are created immediately in `PAX_SLK`.
- The later `a/` entry is treated as `PAX_DIR` and routed to `node_creat()`.
- In tar mode with `-L`, directory handling enters the symlink-following loop.
- For `a -> a`, `lstat("a")` keeps reporting a symlink and `readlink("a")` keeps returning `a`.
- `nm` is reassigned to the same target repeatedly, so `mkdir()` is never reached.

A local reproduction of the loop condition with `ln -s a a` confirmed repeated `lstat()` / `readlink()` iterations over the same path.

## Why This Is A Real Bug

The behavior is attacker-triggerable under normal `tar -xL` extraction semantics. The archive author controls both the symlink and the later directory entry, while the extractor supplies the `-L` option. Because the loop has no visited set, depth limit, or unchanged-target check, a single archive can make extraction hang indefinitely.

## Fix Requirement

Limit symlink traversal during directory creation and fail safely when traversal exceeds the allowed depth.

## Patch Rationale

The patch adds a `SYMLOOP_MAX` fallback definition and counts followed symlinks in the `PAX_DIR` / `OP_TAR` / `Lflag` path. If traversal exceeds the limit, extraction returns `-1` with `errno = ELOOP` and emits the existing symlink-chain warning style.

This prevents infinite traversal while preserving normal symlink-following behavior for finite chains.

## Residual Risk

None

## Patch

```diff
diff --git a/bin/pax/file_subs.c b/bin/pax/file_subs.c
index c679edf..bb1b722 100644
--- a/bin/pax/file_subs.c
+++ b/bin/pax/file_subs.c
@@ -46,6 +46,10 @@
 #include "pax.h"
 #include "extern.h"
 
+#ifndef SYMLOOP_MAX
+#define SYMLOOP_MAX 32
+#endif
+
 static int fset_ids(char *, int, uid_t, gid_t);
 static int unlnk_exist(char *, int);
 static int chk_path(char *, uid_t, gid_t, int);
@@ -356,7 +360,7 @@ node_creat(ARCHD *arcn)
 	struct stat sb;
 	char target[PATH_MAX];
 	char *nm = arcn->name;
-	int len, defer_pmode = 0;
+	int len, symlinks, defer_pmode = 0;
 
 	/*
 	 * create node based on type, if that fails try to unlink the node and
@@ -375,8 +379,16 @@ node_creat(ARCHD *arcn)
 			 * directory.
 			 */
 			if (op_mode == OP_TAR && Lflag) {
+				symlinks = 0;
 				while (lstat(nm, &sb) == 0 &&
 				    S_ISLNK(sb.st_mode)) {
+					if (++symlinks > SYMLOOP_MAX) {
+						errno = ELOOP;
+						syswarn(0, errno,
+						   "cannot follow symlink %s in chain for %s",
+						    nm, arcn->name);
+						return(-1);
+					}
 					len = readlink(nm, target,
 					    sizeof target - 1);
 					if (len == -1) {
```