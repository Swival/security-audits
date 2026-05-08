# Account Lock Omits Shell Marker For Long Shells

## Classification

security_control_failure, high severity, certain confidence

## Affected Locations

`usr.sbin/user/user.c:1050`

## Summary

`usermod -Z` is intended to lock an account by appending `-` to the user’s login shell and prepending `*` to the password hash. For shells with length at least `MaxShellNameLen` (`256`), the shell lock path allocated enough heap space for the original shell plus marker, but copied and appended using the size of a fixed 256-byte stack buffer. As a result, the shell string was truncated before the `-` marker could be written, and the account lock could complete without the shell-based lock marker.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- The target local account has an existing login shell length of at least `MaxShellNameLen`.
- A caller invokes the account lock control path, e.g. `usermod -Z`.
- The truncated shell prefix remains a valid executable shell for relevant authentication paths.

## Proof

In `moduser`, the `F_ACCTLOCK` branch allocated `shell_tmp` with:

```c
malloc(strlen(pwp->pw_shell) + sizeof(acctlock_str))
```

This is sufficient for the full current shell plus the `"-"` marker and NUL terminator because `acctlock_str` is `char acctlock_str[] = "-"`.

However, the copy operations used `sizeof(shell_len)`, where `shell_len` was a fixed stack buffer:

```c
char shell_len[MaxShellNameLen];

strlcpy(shell_tmp, pwp->pw_shell, sizeof(shell_len));
strlcat(shell_tmp, acctlock_str, sizeof(shell_len));
```

For a shell length `>= 256`, `strlcpy(..., 256)` writes only a 255-byte prefix plus NUL. `strlcat(..., "-", 256)` then has no available room to append `-`. The code assigns the unmarked truncated value to `pwp->pw_shell`, and the modified passwd entry is later serialized to `/etc/master.passwd`.

The finding was reproduced: `usermod -Z` can return after password locking while omitting the shell account-lock marker.

## Why This Is A Real Bug

The bug is a fail-open security-control failure. The caller requested account locking, but the shell lock marker is not written for long shell paths.

This is security-relevant because authentication may still proceed through non-password methods. OpenSSH’s user admission path checks whether the configured shell exists and is executable before public-key authentication can continue. If the 255-byte truncated shell prefix is executable, password locking alone does not enforce the intended shell-based account lock.

## Fix Requirement

Use the allocated `shell_tmp` buffer size for both `strlcpy` and `strlcat` in the `F_ACCTLOCK` path, rather than the unrelated fixed-size `shell_len` stack buffer.

## Patch Rationale

The patch removes the unused fixed stack buffer and stores the actual allocation size in `shell_buf`:

```c
shell_buf = strlen(pwp->pw_shell) + sizeof(acctlock_str);
shell_tmp = malloc(shell_buf);
```

Both bounded string operations now use `shell_buf`:

```c
strlcpy(shell_tmp, pwp->pw_shell, shell_buf);
strlcat(shell_tmp, acctlock_str, shell_buf);
```

This makes the copy bounds match the heap allocation and guarantees space for the `-` marker and NUL terminator.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/user/user.c b/usr.sbin/user/user.c
index b1bea38..ed0022c 100644
--- a/usr.sbin/user/user.c
+++ b/usr.sbin/user/user.c
@@ -1450,7 +1450,6 @@ moduser(char *login_name, char *newlogin, user_t *up)
 	char		acctlock_str[] = "-";
 	char		pwlock_str[] = "*";
 	char		pw_len[PasswordLength + 1];
-	char		shell_len[MaxShellNameLen];
 	char		*shell_last_char;
 	size_t		colonc, loginc;
 	size_t		cc;
@@ -1549,14 +1548,15 @@ moduser(char *login_name, char *newlogin, user_t *up)
 		if (up->u_flags & F_ACCTLOCK) {
 			/* lock the account */
 			if (*shell_last_char != *acctlock_str) {
-				shell_tmp = malloc(strlen(pwp->pw_shell) + sizeof(acctlock_str));
+				shell_buf = strlen(pwp->pw_shell) + sizeof(acctlock_str);
+				shell_tmp = malloc(shell_buf);
 				if (shell_tmp == NULL) {
 					close(ptmpfd);
 					pw_abort();
 					errx(EXIT_FAILURE, "account lock: cannot allocate memory");
 				}
-				strlcpy(shell_tmp, pwp->pw_shell, sizeof(shell_len));
-				strlcat(shell_tmp, acctlock_str, sizeof(shell_len));
+				strlcpy(shell_tmp, pwp->pw_shell, shell_buf);
+				strlcat(shell_tmp, acctlock_str, shell_buf);
 				pwp->pw_shell = shell_tmp;
 			} else {
 				locked++;
```