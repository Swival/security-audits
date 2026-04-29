# chroot guard accepts traversal into protected directories

## Classification

High severity security control failure.

Confidence: certain.

## Affected Locations

- `src/fsio.c:148`

## Summary

`chroot_allow_path()` is intended to block write-like operations against sensitive chroot paths under `/etc` and `/lib`, but it checked the caller-supplied path string before removing dot segments. A path such as `/tmp/../etc/passwd` did not match the guarded prefixes, while the later kernel operation resolved it to `/etc/passwd`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `fsio_guard_chroot` is enabled.
- Caller can perform a write-like filesystem operation.
- Caller can supply an absolute path containing dot-segment traversal.

## Proof

- `chroot_allow_path()` implements the sensitive-path guard for `/etc` and `/lib`.
- Before the patch, it compared the raw path against exact `/etc` and `/lib`, or prefixes `/etc/` and `/lib/`.
- Dot segments were not cleaned before the comparison.
- `sys_open()` calls `chroot_allow_path()` for `O_APPEND`, `O_CREAT`, `O_TRUNC`, and `O_WRONLY`.
- `sys_open()` then passes the original path to `open(2)`, where `/tmp/../etc/passwd` resolves to `/etc/passwd`.
- Therefore `/tmp/../etc/passwd` bypassed the guard even though it targeted a protected path.

## Why This Is A Real Bug

The guard and the kernel evaluated different path forms. The guard evaluated the unnormalized string, while the filesystem resolved dot segments during the actual operation. This creates a deterministic fail-open condition in a security control specifically intended to protect sensitive chroot paths.

## Fix Requirement

Canonicalize or clean absolute paths before applying guarded-prefix checks so the policy decision is made on the same effective path shape that filesystem resolution will use for dot segments.

## Patch Rationale

The patch normalizes the input path inside `chroot_allow_path()` using `pr_fs_clean_path()` before computing length and checking `/etc` and `/lib` prefixes. This makes `/tmp/../etc/passwd` become `/etc/passwd` for the guard decision, causing the existing rejection logic to apply.

## Residual Risk

None

## Patch

```diff
diff --git a/src/fsio.c b/src/fsio.c
index c72102cd9..cb71f1873 100644
--- a/src/fsio.c
+++ b/src/fsio.c
@@ -124,6 +124,7 @@ static const char *trace_channel = "fsio";
  * Currently, we guard the /etc and /lib directories.
  */
 static int chroot_allow_path(const char *path) {
+  char cleaned_path[PR_TUNABLE_PATH_MAX + 1] = {'\0'};
   size_t path_len;
   int res = 0;
 
@@ -131,6 +132,9 @@ static int chroot_allow_path(const char *path) {
    * ever not be the case, this check will not work.
    */
 
+  pr_fs_clean_path(path, cleaned_path, sizeof(cleaned_path)-1);
+  path = cleaned_path;
+
   path_len = strlen(path);
   if (path_len < 4) {
     /* Path is not long enough to include one of the guarded directories. */
```