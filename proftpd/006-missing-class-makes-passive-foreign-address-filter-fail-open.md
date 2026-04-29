# Missing Class Makes Passive Foreign-Address Filter Fail Open

## Classification

Authorization bypass, medium severity.

## Affected Locations

`src/inet.c:1698`

## Summary

A passive FTP data connection from a foreign IP address is accepted when `AllowForeignAddress` is configured with a nonexistent class name. The passive accept path logs that the `<Class>` was not found, but then falls through to open the data connection instead of rejecting it.

## Provenance

Verified and reproduced from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

`AllowForeignAddress` references a nonexistent `Class` and is not configured as `TRUE` or `FALSE`.

## Proof

`modules/mod_core.c:2359` treats any non-boolean `AllowForeignAddress` value as a class name and stores `-1` plus the class string at `modules/mod_core.c:2365`, without validating that the class exists.

Passive transfers reach `src/data.c:146`, which calls `pr_inet_accept()` for the passive listener.

In `src/inet.c`, when the accepted passive peer address differs from the control connection address, the code enters the class-filter branch and calls `pr_class_find(class_name)`. If the class exists, `pr_class_satisfied()` rejects nonmembers. If `pr_class_find()` returns `NULL`, the vulnerable code only logs:

```c
pr_log_debug(DEBUG8, "<Class> '%s' not found for filtering "
  "AllowForeignAddress", class_name);
```

Execution then falls through to:

```c
d->mode = CM_OPEN;
res = pr_inet_openrw(p, d, NULL, PR_NETIO_STRM_DATA, fd, rfd, wfd,
  resolve);
```

Thus, a passive data connection from a foreign IP address is accepted when the configured class name is missing.

The active `PORT`/`EPRT` paths do not share this fail-open behavior because their missing-class branch leaves `allow_foreign_addr` false and later rejects mismatches.

## Why This Is A Real Bug

The directive is an authorization control for whether data connections from foreign IP addresses are allowed. A nonexistent class means the configured authorization filter cannot be evaluated. Accepting the connection in that state allows an unauthorized foreign host to open the session data connection, contrary to the intended policy.

This is a fail-open authorization decision caused by treating a missing policy object as non-fatal in the passive path.

## Fix Requirement

When `AllowForeignAddress` names a class and `pr_class_find(class_name)` returns `NULL`, reject the passive foreign-address data connection before calling `pr_inet_openrw()`.

## Patch Rationale

The patch converts the missing-class case from fail-open to fail-closed. It closes the accepted socket, marks the data connection as an access error, sets `d->xerrno = EACCES`, and returns `NULL`.

This matches the existing rejection behavior used when a class exists but the foreign peer does not satisfy it.

## Residual Risk

None

## Patch

```diff
diff --git a/src/inet.c b/src/inet.c
index 193223fe1..96163facb 100644
--- a/src/inet.c
+++ b/src/inet.c
@@ -1698,6 +1698,11 @@ conn_t *pr_inet_accept(pool *p, conn_t *d, conn_t *c, int rfd, int wfd,
             } else {
               pr_log_debug(DEBUG8, "<Class> '%s' not found for filtering "
                 "AllowForeignAddress", class_name);
+
+              (void) close(fd);
+              d->mode = CM_ERROR;
+              d->xerrno = EACCES;
+              return NULL;
             }
 
           } else {
```