# Source Server Escapes Remote Target Directory

## Classification

Path traversal. Severity: high. Confidence: certain.

## Affected Locations

`scp.c:1725`

## Summary

During SFTP remote-to-remote copies through the local client, `throughlocal_sftp` uses source-server-controlled glob results to build the destination path. If a malicious source SFTP server returns a match whose basename is `..`, the destination path becomes `target/..`, causing copied content to be written into the parent of the requested destination directory.

## Provenance

Verified from the supplied source, reproduced by static data-flow review, and reported by Swival Security Scanner: https://swival.dev

## Preconditions

User runs an SFTP remote-to-remote copy through the local client.

## Proof

`throughlocal_sftp` is invoked for SFTP remote-to-remote copies through the local client from `toremote`.

The vulnerable flow is:

1. `throughlocal_sftp` obtains source-controlled matches from:
   - `sftp_glob(from, abs_src, GLOB_NOCHECK|GLOB_MARK, NULL, &g)`

2. For each match, it derives the destination filename from the attacker-controlled path:
   - `tmp = xstrdup(g.gl_pathv[i])`
   - `filename = basename(tmp)`

3. Before the patch, there was no special handling for:
   - `filename == ".."`

4. If the destination is a directory, the destination path was built as:
   - `abs_dst = sftp_path_append(target, filename)`

5. Therefore a malicious source glob result with basename `..` produced:
   - `abs_dst = target/..`

6. Recursive copies then passed this escaped destination to:
   - `sftp_crossload_dir(from, to, g.gl_pathv[i], abs_dst, ...)`

This causes attacker-controlled source contents to be created or truncated under the destination parent directory instead of under the requested target.

## Why This Is A Real Bug

The same invariant is already enforced elsewhere. `sink_sftp` explicitly remaps a remote basename of `..` to `.` before appending it to the local destination:

```c
/* Special handling for destination of '..' */
if (strcmp(filename, "..") == 0)
	filename = "."; /* Download to dest, not dest/.. */
```

`throughlocal_sftp` performs the same kind of destination path construction for remote-to-remote SFTP copies, but lacked the equivalent guard. Since `sftp_path_append` concatenates path components and does not neutralize `..`, the missing check allows traversal out of the requested destination directory.

## Fix Requirement

Reject or remap a basename of `..` before constructing `abs_dst` in `throughlocal_sftp`.

## Patch Rationale

The patch mirrors the existing `sink_sftp` behavior by remapping `..` to `.` before calling `sftp_path_append`. This preserves compatibility with unusual source matches while ensuring a malicious basename cannot turn the requested destination directory into its parent.

## Residual Risk

None

## Patch

```diff
diff --git a/scp.c b/scp.c
index 2ec3d49..43a421f 100644
--- a/scp.c
+++ b/scp.c
@@ -1990,6 +1990,10 @@ throughlocal_sftp(struct sftp_conn *from, struct sftp_conn *to,
 			goto out;
 		}
 
+		/* Special handling for destination of '..' */
+		if (strcmp(filename, "..") == 0)
+			filename = "."; /* Copy to dest, not dest/.. */
+
 		if (targetisdir)
 			abs_dst = sftp_path_append(target, filename);
 		else
```