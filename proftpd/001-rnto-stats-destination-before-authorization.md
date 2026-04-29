# RNTO Stats Destination Before Authorization

## Classification

Information disclosure, medium severity.

## Affected Locations

`modules/mod_core.c:6367`

## Summary

`core_rnto()` checked destination path existence with `pr_fsio_stat()` before verifying RNTO authorization with `dir_check_canon()`. When `AllowOverwrite` was disabled or unset, an authenticated FTP client could distinguish existing unauthorized destination paths from nonexistent unauthorized destination paths by comparing different RNTO error responses.

## Provenance

Identified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Attacker is an authenticated FTP client.
- `RNFR` has already set `session.xfer.path`.
- `AllowOverwrite` is disabled or unset.
- The RNTO destination is in a directory denied by FTP authorization, such as `<Limit>`.
- The server process can still perform `stat(2)` on the destination path.

## Proof

In `core_rnto()`:

- The attacker-controlled RNTO argument is decoded.
- Path filters are applied.
- The path is canonicalized with `dir_canonical_path()`.
- Before authorization, `AllowOverwrite` is read and `pr_fsio_stat(path, &st)` is called.
- If the unauthorized destination exists and overwrites are disallowed, the function returns `550 <arg>: Rename permission denied`.
- If the unauthorized destination does not exist, `pr_fsio_stat()` fails, execution reaches `dir_check_canon()`, and the denied directory returns `550 <arg>: Operation not permitted`.

This creates a response oracle for file existence outside the authorized rename destination scope.

## Why This Is A Real Bug

Authorization must precede filesystem metadata probes for paths the client is not allowed to target. Here, the RNTO handler performed an existence check on the destination before confirming that the user was authorized to rename into that destination. Because the pre-authorization `stat(2)` result selected a different error path, the FTP response disclosed whether a denied destination name existed.

## Fix Requirement

Move the `dir_check_canon()` authorization check so it runs immediately after canonicalization and before any `AllowOverwrite` lookup or `pr_fsio_stat()` overwrite check.

## Patch Rationale

The patch preserves existing RNTO validation order through decoding, path filtering, and canonicalization, then performs the existing destination authorization check before metadata access. Unauthorized destinations now fail at the same authorization gate regardless of whether the path exists, removing the existence oracle. Authorized destinations still proceed to the existing `AllowOverwrite` and `pr_fsio_stat()` logic, preserving intended overwrite behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_core.c b/modules/mod_core.c
index 91298231a..ee7ba380c 100644
--- a/modules/mod_core.c
+++ b/modules/mod_core.c
@@ -6366,6 +6366,17 @@ MODRET core_rnto(cmd_rec *cmd) {
 
   path = dir_canonical_path(cmd->tmp_pool, path);
 
+  if (!path ||
+      !dir_check_canon(cmd->tmp_pool, cmd, cmd->group, path, NULL)) {
+    pr_log_debug(DEBUG8, "%s command denied by <Limit> config",
+      (char *) cmd->argv[0]);
+    pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(EPERM));
+
+    pr_cmd_set_errno(cmd, EPERM);
+    errno = EPERM;
+    return PR_ERROR(cmd);
+  }
+
   allow_overwrite = get_param_ptr(CURRENT_CONF, "AllowOverwrite", FALSE);
 
   /* Deny the rename if AllowOverwrites are not allowed, and the destination
@@ -6382,17 +6393,6 @@ MODRET core_rnto(cmd_rec *cmd) {
     return PR_ERROR(cmd);
   }
 
-  if (!path ||
-      !dir_check_canon(cmd->tmp_pool, cmd, cmd->group, path, NULL)) {
-    pr_log_debug(DEBUG8, "%s command denied by <Limit> config",
-      (char *) cmd->argv[0]);
-    pr_response_add_err(R_550, _("%s: %s"), cmd->arg, strerror(EPERM));
-
-    pr_cmd_set_errno(cmd, EPERM);
-    errno = EPERM;
-    return PR_ERROR(cmd);
-  }
-
   res = pr_fsio_rename_with_error(cmd->pool, session.xfer.path, path, &err);
   if (res < 0) {
     int xerrno = errno;
```