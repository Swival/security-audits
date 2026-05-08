# System Rhosts Negative Entries Do Not Stop Later User-File Acceptance

## Classification

Authentication bypass; high severity.

## Affected Locations

`usr.bin/ssh/auth-rhosts.c:128`

## Summary

A system-wide negative rhosts entry in `/etc/hosts.equiv` or `shosts.equiv` is treated the same as no match. As a result, `auth_rhosts2()` continues to check per-user `.shosts` and `.rhosts` files. If a user file contains a later positive match for the same remote host/user, authentication is accepted despite the system-wide deny.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Rhosts/hostbased authentication is enabled.
- The target is not logging in as root, because root ignores system host files.
- A system-wide rhosts file contains a matching negative entry for the remote host/user.
- The target user has `.shosts` or `.rhosts` enabled and containing a matching positive entry.
- Strict mode checks and host key/signature validation otherwise pass.

## Proof

Example configuration:

```text
/etc/hosts.equiv:
-bad.example attacker

~victim/.rhosts:
bad.example attacker
```

Observed control flow:

- `check_rhosts_file()` matches the negative system entry and records it as negated.
- Before the patch, the negative match returns `0`, the same value used for no match.
- `auth_rhosts2()` only accepts system files on a true return and does not distinguish a deny from no match.
- Execution then proceeds to per-user `.shosts` and `.rhosts` checks.
- The positive user-file match returns `1`.
- `auth_rhosts2()` returns success, allowing hostbased authentication to continue.

## Why This Is A Real Bug

A root-owned system-wide negative rhosts entry is intended to deny access for a matching remote host/user. Returning `0` for that deny makes it indistinguishable from “no matching entry,” so the deny has no blocking effect when a user-controlled file later permits the same principal. This bypasses the administrator’s system-wide rhosts policy under the documented enabled-feature configuration.

## Fix Requirement

Negative matches must be represented distinctly from “no match,” and `auth_rhosts2()` must immediately fail authentication when a system-wide file returns a negative match.

## Patch Rationale

The patch changes `check_rhosts_file()` to return three states:

- `1`: positive match; authentication may be granted.
- `0`: no match or unusable file; continue existing fallback behavior.
- `-1`: negative match; access is explicitly denied.

`auth_rhosts2()` now checks system-wide files for `r < 0` and returns failure immediately. Positive system-file matches still return success. Per-user file handling continues to accept only `r > 0`; negative per-user entries remain non-accepting and do not accidentally authenticate.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ssh/auth-rhosts.c b/usr.bin/ssh/auth-rhosts.c
index 3717e93..ab36a20 100644
--- a/usr.bin/ssh/auth-rhosts.c
+++ b/usr.bin/ssh/auth-rhosts.c
@@ -46,7 +46,8 @@ extern ServerOptions options;
 /*
  * This function processes an rhosts-style file (.rhosts, .shosts, or
  * /etc/hosts.equiv).  This returns true if authentication can be granted
- * based on the file, and returns zero otherwise.
+ * based on the file, -1 if access is denied by a negative entry, and zero
+ * otherwise.
  */
 
 static int
@@ -167,7 +168,7 @@ check_rhosts_file(const char *filename, const char *hostname,
 		if (negated) {
 			auth_debug_add("Matched negative entry in %.100s.",
 			    filename);
-			return 0;
+			return -1;
 		}
 		/* Accept authentication. */
 		return 1;
@@ -235,14 +236,20 @@ auth_rhosts2(struct passwd *pw, const char *client_user, const char *hostname,
 	if (pw->pw_uid == 0)
 		debug3_f("root user, ignoring system hosts files");
 	else {
-		if (check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
-		    client_user, pw->pw_name)) {
+		r = check_rhosts_file(_PATH_RHOSTS_EQUIV, hostname, ipaddr,
+		    client_user, pw->pw_name);
+		if (r < 0)
+			return 0;
+		if (r > 0) {
 			auth_debug_add("Accepted for %.100s [%.100s] by "
 			    "/etc/hosts.equiv.", hostname, ipaddr);
 			return 1;
 		}
-		if (check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
-		    client_user, pw->pw_name)) {
+		r = check_rhosts_file(_PATH_SSH_HOSTS_EQUIV, hostname, ipaddr,
+		    client_user, pw->pw_name);
+		if (r < 0)
+			return 0;
+		if (r > 0) {
 			auth_debug_add("Accepted for %.100s [%.100s] by "
 			    "%.100s.", hostname, ipaddr, _PATH_SSH_HOSTS_EQUIV);
 			return 1;
@@ -312,8 +319,9 @@ auth_rhosts2(struct passwd *pw, const char *client_user, const char *hostname,
 			continue;
 		}
 		/* Check if authentication is permitted by the file. */
-		if (check_rhosts_file(path, hostname, ipaddr,
-		    client_user, pw->pw_name)) {
+		r = check_rhosts_file(path, hostname, ipaddr,
+		    client_user, pw->pw_name);
+		if (r > 0) {
 			auth_debug_add("Accepted by %.100s.",
 			    rhosts_files[rhosts_file_index]);
 			/* Restore the privileged uid. */
```