# FTP Username Traverses Directory Lastlog Path

## Classification

Path traversal; high severity.

## Affected Locations

`src/lastlog.c:64`

## Summary

When `PR_LASTLOG_PATH` is a directory, `log_lastlog()` constructs the lastlog target path by appending the authenticated FTP username directly to the directory path. A username containing path traversal syntax can escape the lastlog directory and cause the daemon to create or overwrite daemon-accessible filesystem paths with lastlog records.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `PR_USE_LASTLOG` is enabled.
- `PR_LASTLOG_PATH` exists and is a directory.
- The attacker can authenticate as, or cause acceptance of, a username containing path traversal components such as `../target`.

## Proof

`log_lastlog()` receives `user_name` and checks whether `PR_LASTLOG_PATH` is a directory. If it is, the vulnerable code builds a path using:

```c
pr_snprintf(path, sizeof(path), "%s/%s", PR_LASTLOG_PATH, user_name);
```

It then opens the resulting path with:

```c
open(path, O_RDWR|O_CREAT, 0600)
```

and writes a `struct lastlog` to that file descriptor.

No validation rejects `/`, `.`, or `..` before the path is constructed. With `UseLastlog on` and an accepted account named `../target`, a successful FTP login causes a privileged open/write to:

```text
PR_LASTLOG_PATH/../target
```

This creates or overwrites a daemon-accessible path outside the intended lastlog directory.

The reproduced authentication path confirms that `session.user` can be populated from the canonical username and passed to `log_lastlog()` during successful login.

## Why This Is A Real Bug

The username is attacker-influenced and is used as a filesystem path component without sanitization. In directory mode, lastlog storage intends to write under `PR_LASTLOG_PATH`, but path separators and dot components allow resolution outside that directory.

Because the write occurs during successful login and the lastlog update opens the target with `O_RDWR|O_CREAT`, the impact is filesystem creation or overwrite wherever the daemon has sufficient access.

## Fix Requirement

Reject unsafe username path components before constructing the directory-mode lastlog path.

At minimum, directory-mode lastlog filenames must not allow:

- `/` path separators.
- `.` as a complete component.
- `..` as a complete component.

## Patch Rationale

The patch adds validation before `PR_LASTLOG_PATH` and `user_name` are joined:

```c
if (strchr(user_name, '/') != NULL || strcmp(user_name, ".") == 0 ||
    strcmp(user_name, "..") == 0) {
  errno = EINVAL;
  return -1;
}
```

This prevents usernames from introducing nested paths or parent-directory traversal when `PR_LASTLOG_PATH` is a directory. Returning `EINVAL` fails the lastlog update safely before any filesystem path is opened.

## Residual Risk

None

## Patch

```diff
diff --git a/src/lastlog.c b/src/lastlog.c
index 898582636..95156a1d8 100644
--- a/src/lastlog.c
+++ b/src/lastlog.c
@@ -55,6 +55,12 @@ int log_lastlog(uid_t uid, const char *user_name, const char *tty,
   }
 
   if (S_ISDIR(st.st_mode)) {
+    if (strchr(user_name, '/') != NULL || strcmp(user_name, ".") == 0 ||
+        strcmp(user_name, "..") == 0) {
+      errno = EINVAL;
+      return -1;
+    }
+
     memset(path, '\0', sizeof(path));
     pr_snprintf(path, sizeof(path), "%s/%s", PR_LASTLOG_PATH, user_name);
     path[sizeof(path)-1] = '\0';
```