# Export Paths Escape Host Mount Root

## Classification

Path traversal, high severity.

## Affected Locations

`usr.sbin/amd/amd/host_ops.c:67`

## Summary

`amd` accepted attacker-controlled NFS export paths from `MOUNTPROC_EXPORT` and concatenated them with the configured automount root without rejecting `..` path components. A malicious mountd server could advertise an export such as `/../../target`, causing `amd` to create/check/use a mountpoint that resolves outside `mf->mf_mount` and mount attacker-controlled NFS content there.

## Provenance

Verified by reproduced analysis and patched from a Swival Security Scanner finding.

Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `amd` is configured to automount the attacker's host map.
- The attacker controls or can impersonate the NFS mountd server used for the host map.
- The attacker returns an export list entry containing canonical path traversal components such as `/..` or `/../`.

## Proof

- `host_fmount` fetches the remote export list via `MOUNTPROC_EXPORT` into `exlist`.
- XDR decoding assigns attacker-controlled export names to `ex_dir` at `usr.sbin/amd/rpcx/mount_xdr.c:160`.
- `MAKE_MNTPT` concatenates `mf->mf_mount` and `ex->ex_dir` directly at `usr.sbin/amd/amd/host_ops.c:67`.
- An export like `/../../../../tmp/evil` becomes a local mount path under string concatenation but resolves outside the configured automount root.
- The unchecked path is used for `already_mounted`, then `mkdirs`, `stat`, and `mount_nfs_fh` through `do_mount`.
- `mount_nfs_fh` passes the path unchanged to `mount(2)` at `usr.sbin/amd/amd/mount_fs.c:89`.
- The filehandle mounted there is fetched for the same attacker-controlled export name via `MOUNTPROC_MNT`.

## Why This Is A Real Bug

The export path is attacker-controlled remote input. `MAKE_MNTPT` treats it as a safe suffix but does not canonicalize it or reject parent-directory traversal. Because subsequent mountpoint creation, validation, and `mount(2)` use the derived path unchanged, pathname resolution can escape the intended automount root. This permits attacker-controlled NFS content to be mounted over an existing local directory or over a directory created by `mkdirs`, causing denial of service and integrity impact.

## Fix Requirement

Reject non-canonical export paths containing `..` as a complete path component before constructing local mountpoints or fetching/mounting filehandles for those exports.

## Patch Rationale

The patch adds `valid_export_path()` and filters each export before `MAKE_MNTPT` is called. The helper rejects `..` only when it appears as a complete path component, including leading, middle, and trailing forms:

- `..`
- `/..`
- `/../`
- `../`
- `/a/../b`
- `/a/..`

It does not reject benign names that merely contain the substring, such as `/foo..bar` or `/..hidden`, because those are not parent-directory path components.

Filtering during construction of the export pointer array prevents invalid exports from reaching the later skip check, filehandle fetch, mountpoint construction, `mkdirs`, `stat`, or `mount_nfs_fh` paths.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/amd/amd/host_ops.c b/usr.sbin/amd/amd/host_ops.c
index 33774db..b431d7a 100644
--- a/usr.sbin/amd/amd/host_ops.c
+++ b/usr.sbin/amd/amd/host_ops.c
@@ -206,6 +206,20 @@ already_mounted(mntlist *mlist, char *dir)
 	return 0;
 }
 
+static int
+valid_export_path(const char *dir)
+{
+	const char *cp = dir;
+
+	while ((cp = strstr(cp, "..")) != NULL) {
+		if ((cp == dir || cp[-1] == '/') &&
+		    (cp[2] == '/' || cp[2] == '\0'))
+			return FALSE;
+		cp += 2;
+	}
+	return TRUE;
+}
+
 /*
  * Mount the export tree from a host
  */
@@ -297,6 +311,8 @@ host_fmount(mntfs *mf)
 	 */
 	ep = xreallocarray(NULL, n_export, sizeof *ep);
 	for (j = 0, ex = exlist; ex; ex = ex->ex_next) {
+		if (!valid_export_path(ex->ex_dir))
+			continue;
 		MAKE_MNTPT(mntpt, ex, mf);
 		if (!already_mounted(mlist, mntpt))
 			ep[j++] = ex;
```