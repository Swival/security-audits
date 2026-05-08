# Forced Login Root Instance Grants Root Context

## Classification

High severity privilege escalation.

## Affected Locations

`usr.bin/login/login.c:412`

## Summary

A non-root local user can invoke setuid-root `login` with `-f ownuser/root` on a secure tty and obtain a root-context shell without authenticating as root.

The bug occurs because `-f` remains enabled for the caller's own account while the `/root` login instance sets `rootlogin`. Authentication is skipped, but later `setusercontext()` receives uid `0` because `rootlogin` is true.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `login` is installed setuid root.
- The caller is a lower-privileged local user.
- The caller runs from a tty marked secure.
- The caller supplies their own valid username with a `/root` instance suffix.

## Proof

The reproduced exploit path is:

- `usr.bin/login/login.c:201` accepts `-f` without restricting it to uid `0`.
- `usr.bin/login/login.c:410` parses `ownuser/root`, sets `rootlogin = 1`, then truncates the username at `/`.
- `usr.bin/login/login.c:457` only clears `fflag` when the real uid differs from `pwd->pw_uid`; for the caller's own account, `fflag` remains set.
- `usr.bin/login/login.c:466` skips `auth_verify()` while `fflag` is set.
- `usr.bin/login/login.c:506` permits root login on secure ttys.
- `usr.bin/login/login.c:713` calls `setusercontext()` with uid `0` when `rootlogin` is true.
- `usr.bin/login/login.c:745` executes the user's shell after root context has been installed.

Concrete trigger:

```sh
login -f ownuser/root
```

Impact: root shell without root authentication.

## Why This Is A Real Bug

The control flow combines two individually sensitive features incorrectly:

- `-f` means the login is treated as pre-authenticated.
- `/root` instance syntax causes the login to be treated as root-context.
- The existing `fflag` clearing logic validates only that the caller owns the base account, not that the requested instance escalates to root.
- The later uid selection trusts `rootlogin`, not `pwd->pw_uid`.

Therefore a user authenticating as themselves can cross into uid `0` solely through instance parsing.

## Fix Requirement

A forced login must not remain forced when the parsed login request is a root login or root instance.

Acceptable fixes include:

- Rejecting root instances for non-root callers.
- Clearing `fflag` whenever `rootlogin` is set.

## Patch Rationale

The patch clears `fflag` when `rootlogin` is true:

```diff
-		if (!pwd || (uid && uid != pwd->pw_uid))
+		if (!pwd || rootlogin || (uid && uid != pwd->pw_uid))
 			fflag = 0;
```

This preserves existing behavior for normal forced logins while ensuring any root-context login must pass through authentication. It directly closes the bypass because `auth_verify()` can no longer be skipped for `/root` instance requests.

## Residual Risk

None

## Patch

`028-forced-login-root-instance-grants-root-context.patch`

```diff
diff --git a/usr.bin/login/login.c b/usr.bin/login/login.c
index 3f2155e..37a0036 100644
--- a/usr.bin/login/login.c
+++ b/usr.bin/login/login.c
@@ -454,7 +454,7 @@ main(int argc, char *argv[])
 		 * Turn off the fflag if we have an invalid user
 		 * or we are not root and we are trying to change uids.
 		 */
-		if (!pwd || (uid && uid != pwd->pw_uid))
+		if (!pwd || rootlogin || (uid && uid != pwd->pw_uid))
 			fflag = 0;
 
 		if (pwd && pwd->pw_uid == 0)
```