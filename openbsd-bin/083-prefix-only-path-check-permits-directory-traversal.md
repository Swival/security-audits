# prefix-only path check permits directory traversal

## Classification

Path traversal, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/npppd/npppd/privsep.c:994`

## Summary

The privileged npppd helper allowed read-only `PRIVSEP_OPEN` requests for any path whose raw string began with `NPPPD_DIR "/"`. Because the check used only a literal prefix comparison, a compromised jailed child could send paths such as `/etc/npppd/../master.passwd`, pass validation, and cause the privileged helper to open a file outside `/etc/npppd`.

## Provenance

Verified and patched from the supplied reproduced finding. Scanner provenance: [Swival Security Scanner](https://swival.dev).

## Preconditions

- A compromised npppd jailed child can send a `PRIVSEP_OPEN` imsg to the privileged helper.
- The target file outside `NPPPD_DIR` is readable by the privileged helper.
- The request uses permitted read-only flags, e.g. `O_RDONLY`.

## Proof

The `PRIVSEP_OPEN` dispatch validates attacker-controlled `a->path` with `privsep_npppd_check_open`, then opens the same path with:

```c
open(a->path, a->flags & ~O_CREAT)
```

The allowlist permits read-only paths under `NPPPD_DIR "/"`. `NPPPD_DIR` is `/etc/npppd`, and the prefix check is implemented as `strncmp` over the literal prefix. Therefore:

```text
path="/etc/npppd/../master.passwd"
flags=O_RDONLY
```

passes the string-prefix allowlist, but filesystem resolution by `open` resolves the path outside `/etc/npppd` to `/etc/master.passwd`.

## Why This Is A Real Bug

The security decision is made on an uncanonicalized pathname, while the privileged operation is performed by the filesystem after resolving `..` components. This creates a mismatch between the checked path and the opened file. The flag validation limits the operation to read-only access, but it does not prevent privileged disclosure of files outside the intended directory.

## Fix Requirement

Canonicalize paths accepted under `NPPPD_DIR "/"` and verify that the resolved path still remains under `NPPPD_DIR "/"` before opening. The privileged helper must open the canonicalized path, not the original attacker-supplied traversal string.

## Patch Rationale

The patch adds `realpath` canonicalization for the `NPPPD_DIR "/"` prefix allowlist entry. If canonicalization fails, if the resolved path no longer starts with `/etc/npppd/`, or if copying the resolved path back into `arg->path` would truncate, validation rejects the request. The later `open` therefore receives the resolved in-directory path rather than the original untrusted string.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/privsep.c b/usr.sbin/npppd/npppd/privsep.c
index e2304d9..20cbf28 100644
--- a/usr.sbin/npppd/npppd/privsep.c
+++ b/usr.sbin/npppd/npppd/privsep.c
@@ -981,6 +981,7 @@ static int
 privsep_npppd_check_open(struct PRIVSEP_OPEN_ARG *arg)
 {
 	int i;
+	char path[PATH_MAX];
 	struct _allow_paths {
 		const char *path;
 		int path_is_prefix;
@@ -1001,6 +1002,13 @@ privsep_npppd_check_open(struct PRIVSEP_OPEN_ARG *arg)
 		if (allow_paths[i].path_is_prefix) {
 			if (!startswith(arg->path, allow_paths[i].path))
 				continue;
+			if (strcmp(allow_paths[i].path, NPPPD_DIR "/") == 0) {
+				if (realpath(arg->path, path) == NULL ||
+				    !startswith(path, allow_paths[i].path) ||
+				    strlcpy(arg->path, path, sizeof(arg->path)) >=
+				    sizeof(arg->path))
+					continue;
+			}
 		} else if (strcmp(arg->path, allow_paths[i].path) != 0)
 			continue;
 		if (allow_paths[i].readonly) {
```