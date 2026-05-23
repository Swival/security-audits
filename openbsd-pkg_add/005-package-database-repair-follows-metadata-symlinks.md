# package database repair follows metadata symlinks

## Classification

Information disclosure, medium severity. Confidence: certain.

## Affected Locations

OpenBSD/PkgCheck.pm:696

## Summary

`pkg_check` repairs package database metadata permissions by validating package metadata entries with symlink-following file tests. A writable package database entry named like valid metadata can be a symlink to a sensitive regular file. When root runs forced repair or approves the prompt, `chmod` follows the symlink and makes the target world-readable.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A lower-privileged local user can write package database metadata.
- The user plants an allowed metadata filename, such as `+DESC`, as a symlink to a regular sensitive file.
- Root runs `pkg_check` repair with `-f` or approves the interactive prompt.

## Proof

`check_permissions` iterates package database directory entries and only validates that the basename is present in `@OpenBSD::PackageInfo::info`.

Before the patch:

```perl
my ($perm, $uid, $gid) = (stat $file)[2, 4, 5];
if (!-f $file) {
```

Both `stat $file` and `-f $file` follow symlinks. Therefore, a metadata entry like `+DESC -> /root/secret` is accepted as a regular metadata file if `/root/secret` is a regular file.

If the target lacks world-readable bits, the repair path computes a mode with `0444` set and calls:

```perl
chmod $perm, $path
```

`chmod` follows the symlink path, changing permissions on the target file. The repair path is reachable before `+CONTENTS` validation because `sanity_check` calls `check_permissions` for every installed package directory first.

## Why This Is A Real Bug

The operation is intended to repair package database metadata, not arbitrary files outside the package database. Because metadata validation follows symlinks, an attacker-controlled package metadata symlink can redirect root’s repair action to a sensitive regular file. The result is local information disclosure by making the symlink target world-readable.

## Fix Requirement

Package database metadata repair must not treat symlinks as regular metadata files. It must inspect the directory entry itself with non-following operations and reject or remove symlink entries before any ownership or permission repair is attempted.

## Patch Rationale

The patch changes metadata inspection from `stat` to `lstat` and reuses Perl’s `_` stat cache for the subsequent file-type test:

```diff
-		my ($perm, $uid, $gid) = (stat $file)[2, 4, 5];
-		if (!-f $file) {
+		my ($perm, $uid, $gid) = (lstat $file)[2, 4, 5];
+		if (!-f _) {
```

`lstat` reads metadata for the directory entry itself rather than the symlink target. `-f _` then tests that same non-followed result. A symlink is no longer accepted as a regular metadata file, so the code reaches the existing rejection/removal path instead of calling permission repair on the symlink path.

## Residual Risk

None

## Patch

```diff
diff --git a/OpenBSD/PkgCheck.pm b/OpenBSD/PkgCheck.pm
index 0944681..fc02bbc 100644
--- a/OpenBSD/PkgCheck.pm
+++ b/OpenBSD/PkgCheck.pm
@@ -705,8 +705,8 @@ sub check_permissions($self, $state, $dir)
 			$self->may_unlink($state, $file);
 			next;
 		}
-		my ($perm, $uid, $gid) = (stat $file)[2, 4, 5];
-		if (!-f $file) {
+		my ($perm, $uid, $gid) = (lstat $file)[2, 4, 5];
+		if (!-f _) {
 			$state->errsay("#1 should be a file", $file);
 			$self->may_unlink($state, $file);
 			next;
```