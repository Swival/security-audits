# docroot prefix bypass

## Classification

High severity authorization flaw.

## Affected Locations

`support/suexec.c:550`

## Summary

`suEXEC` validates that the current working directory is under the configured document root using only a byte-prefix comparison:

```c
strncmp(cwd, dwd, strlen(dwd))
```

This accepts sibling paths that share the same prefix as `AP_DOC_ROOT`. For example, if the canonical document root is `/var/www`, a current working directory of `/var/www_evil/cgi-bin` passes the check even though it is outside the document root.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The caller can cause `suexec` to run with a current working directory under a sibling path that shares the `AP_DOC_ROOT` prefix.
- The target CGI path satisfies the later ownership, mode, and executable checks.

## Proof

`cwd` is obtained with `getcwd()` after the process switches to the target UID/GID. `dwd` is the canonicalized configured document root, obtained by `chdir(AP_DOC_ROOT)` followed by `getcwd()`.

The affected check only verifies that the first `strlen(dwd)` bytes match:

```c
if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
    log_err("command not in docroot (%s/%s)\n", cwd, cmd);
    exit(114);
}
```

With:

```text
dwd = /var/www
cwd = /var/www_evil/cgi-bin
```

the comparison succeeds because `/var/www` matches the first bytes of `/var/www_evil/cgi-bin`.

After this point, `support/suexec.c` only checks directory and program type, ownership, writability, setuid/setgid bits, and executable mode. It does not re-check document-root containment before reaching:

```c
execv(cmd, &argv[3]);
```

Reachability is practical from committed code: `modules/generators/mod_cgi.c:396` sets the child working directory to the parent directory of `r->filename`, and `os/unix/unixd.c:147` through `os/unix/unixd.c:178` invokes `suexec` with only the basename as `cmd`. A CGI mapped under a sibling path such as `/var/www_evil/...` can therefore execute outside the intended document root when normal `suEXEC` ownership and mode requirements are met.

## Why This Is A Real Bug

The check is intended to enforce document-root containment, not string-prefix similarity. Paths such as `/var/www_evil` are not descendants of `/var/www`, but the current logic treats them as valid.

The later validation does not compensate for this mistake. It verifies filesystem safety properties of the current directory and program, but it does not ensure that the directory is actually inside `AP_DOC_ROOT`.

## Fix Requirement

After the existing prefix comparison succeeds, require a path boundary:

- `cwd` must equal `dwd`, or
- the next character in `cwd` after the `dwd` prefix must be `/`.

This preserves valid paths such as `/var/www` and `/var/www/cgi-bin`, while rejecting sibling prefixes such as `/var/www_evil`.

## Patch Rationale

The patch extends the existing containment check with an explicit boundary condition:

```c
cwd[strlen(dwd)] == '\0' || cwd[strlen(dwd)] == '/'
```

This keeps the current canonicalization behavior and error handling intact while closing the prefix-confusion bypass.

## Residual Risk

None

## Patch

```diff
diff --git a/support/suexec.c b/support/suexec.c
index c2eb0b6..1e8944a 100644
--- a/support/suexec.c
+++ b/support/suexec.c
@@ -547,7 +547,8 @@ int main(int argc, char *argv[])
         }
     }
 
-    if ((strncmp(cwd, dwd, strlen(dwd))) != 0) {
+    if ((strncmp(cwd, dwd, strlen(dwd))) != 0 ||
+        (cwd[strlen(dwd)] != '\0' && cwd[strlen(dwd)] != '/')) {
         log_err("command not in docroot (%s/%s)\n", cwd, cmd);
         exit(114);
     }
```