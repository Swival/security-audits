# Recursive LIST Follows Symlink Cycles

## Classification

Denial of service, medium severity.

## Affected Locations

- `modules/mod_ls.c:1235`
- `modules/mod_ls.c:577`
- `modules/mod_ls.c:614`
- `modules/mod_ls.c:1488`
- `modules/mod_ls.c:1528`
- `src/fsio.c:3072`

## Summary

Recursive `LIST -R` can follow symlinked directories when `ShowSymlinks` is enabled or `-L` is supplied. Because `mod_ls` does not track visited directories by filesystem identity, an attacker-controlled symlink to an ancestor directory causes repeated recursive `listdir()` calls until CPU, stack, pool memory, or output limits are exhausted.

## Provenance

Verified and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- Authenticated FTP attacker can create a symlink inside a listed directory tree.
- Recursive listing is available via `LIST -R`, or equivalent configured list options.
- Symlink traversal is enabled by `ShowSymlinks` behavior or explicitly requested with `-L`.
- No effective `ListOptions maxdepth`, `maxdirs`, or `maxfiles` limit prevents recursion.

## Proof

The reproduced path is:

- `LIST` option parsing sets `opt_R` for recursive listing and `opt_L` for symlink dereference.
- `listfile()` dereferences symlinks when `opt_L` is set and returns directory status for a symlink that resolves to a directory.
- `is_safe_symlink()` only rejects direct textual `.` / `..` targets and related trivial forms; a target such as `../a` is accepted.
- The recursive loop in `listdir()` calls `pr_fsio_chdir_canon(*r, !opt_L && list_show_symlinks)`.
- With `-L`, the second argument is false, so the symlinked directory is followed.
- `listdir()` then recurses into the same directory tree again without recording visited `dev` / `ino` pairs.
- `pr_fsio_chdir_canon()` has only a local symlink-resolution loop counter, so resolving the same single symlink once per recursive call is not blocked.

A symlink from a child directory back to an ancestor therefore yields unbounded recursive listing.

## Why This Is A Real Bug

The issue is reachable through normal FTP listing behavior by an authenticated user who controls directory contents. Existing checks do not establish a recursion graph invariant:

- Dot entries are skipped only by name.
- `is_safe_symlink()` is textual and incomplete for ancestor references.
- Filesystem canonicalization prevents only per-call symlink resolution loops.
- `listdir()` has no visited-directory state.
- Without configured listing limits, recursion depth and output grow until resource exhaustion or abort.

This is a server-side denial of service in the listing worker.

## Fix Requirement

Recursive listing must remember directory filesystem identities already visited during a single listing operation and refuse to recurse into a directory whose `(st_dev, st_ino)` pair has already been seen.

## Patch Rationale

The patch adds a per-command `list_seen_dirs` array containing `dev_t` and `ino_t` for each visited directory. At the start of recursive `listdir()` processing, it stats `"."` after the current directory change, compares the current directory against previously seen identities, and returns without recursion on a match.

This blocks symlink cycles independently of symlink target spelling, relative path tricks, and canonicalization behavior. Resetting `list_seen_dirs` at the start of `dolist()` scopes the visited set to one listing command and avoids cross-command contamination.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_ls.c b/modules/mod_ls.c
index 3ab883ee5..421fa745c 100644
--- a/modules/mod_ls.c
+++ b/modules/mod_ls.c
@@ -86,10 +86,46 @@ struct list_limit_rec {
   unsigned char logged;
 };
 
+struct list_seen_dir {
+  dev_t dev;
+  ino_t ino;
+};
+
+static array_header *list_seen_dirs = NULL;
+
 static struct list_limit_rec list_ndepth;
 static struct list_limit_rec list_ndirs;
 static struct list_limit_rec list_nfiles;
 
+static int listdir_seen_dir(cmd_rec *cmd) {
+  register unsigned int i;
+  struct list_seen_dir *dirs, *dir;
+  struct stat st;
+
+  pr_fs_clear_cache2(".");
+  if (pr_fsio_stat(".", &st) < 0) {
+    return FALSE;
+  }
+
+  if (list_seen_dirs == NULL) {
+    list_seen_dirs = make_array(cmd->tmp_pool, 8, sizeof(struct list_seen_dir));
+  }
+
+  dirs = list_seen_dirs->elts;
+  for (i = 0; i < list_seen_dirs->nelts; i++) {
+    if (dirs[i].dev == st.st_dev &&
+        dirs[i].ino == st.st_ino) {
+      return FALSE;
+    }
+  }
+
+  dir = push_array(list_seen_dirs);
+  dir->dev = st.st_dev;
+  dir->ino = st.st_ino;
+
+  return TRUE;
+}
+
 /* ls options */
 static int
     opt_1 = 0,
@@ -1375,6 +1411,11 @@ static int listdir(cmd_rec *cmd, pool *workp, const char *resp_code,
     return -1;
   }
 
+  if (opt_R &&
+      !listdir_seen_dir(cmd)) {
+    return 0;
+  }
+
   if (workp == NULL) {
     workp = make_sub_pool(cmd->tmp_pool);
     pr_pool_tag(workp, "mod_ls: listdir(): workp (from cmd->tmp_pool)");
@@ -1909,6 +1950,7 @@ static int dolist(cmd_rec *cmd, const char *opt, const char *resp_code,
   char *arg = (char*) opt;
 
   ls_curtime = time(NULL);
+  list_seen_dirs = NULL;
 
   if (clear_flags) {
     opt_1 = opt_A = opt_a = opt_B = opt_C = opt_d = opt_F = opt_h = opt_n =
```