# Temporary FastCGI socket directory leak on spawn failure

## Classification
- Type: resource lifecycle bug
- Severity: low
- Confidence: certain

## Affected Locations
- `lib/handler/configurator/fastcgi.c:287`

## Summary
When `fastcgi.spawn` creates a temporary FastCGI socket directory with `mkdtemp`, failure paths before the cleanup helper is successfully installed fall through to `Exit:` and call `unlink(dirname)`. Because `dirname` is a directory, that call does not remove it, leaving stale `h2o.fcgisock.*` directories on disk.

## Provenance
- Verified from the provided reproducer and source review
- Scanner reference: https://swival.dev

## Preconditions
- `fastcgi.spawn` executes
- `mkdtemp` succeeds
- Execution reaches a failure path before helper ownership of cleanup is established

## Proof
In `on_config_spawn`, `mkdtemp(dirname)` creates a temporary directory used for the FastCGI socket path and later cleanup. The normal success lifecycle is covered by the spawned helper: `share/h2o/kill-on-close:60` runs `/bin/rm -rf $rmpath` after fd 5 closes, that close is triggered by `spawnproc_on_dispose` in `lib/handler/configurator/fastcgi.c:211`, and handler teardown reaches it from `lib/handler/fastcgi.c:824`.

However, several error paths occur after directory creation but before the helper can take ownership. Examples include `chown(dirname, ...)` failure at `lib/handler/configurator/fastcgi.c:293` and `create_spawnproc(...)` failure returning `-1` at `lib/handler/configurator/fastcgi.c:299`. Those paths go to `Exit:`, where cleanup uses `unlink(dirname)` at `lib/handler/configurator/fastcgi.c:287`. Since `dirname` names a directory, `unlink` does not remove it, so the temporary directory persists.

## Why This Is A Real Bug
The normal runtime cleanup path does not cover these early failures because the helper process is not yet guaranteed to exist and own `rmpath`. On those paths, local cleanup is the only mechanism. Using `unlink` against a directory is ineffective, so each such failed configuration leaves one orphaned temporary directory under `/tmp`. This is externally observable and accumulates over repeated failures.

## Fix Requirement
Replace directory cleanup in the local failure path with `rmdir(dirname)` after socket cleanup, so temporary directories created by `mkdtemp` are actually removed when helper-based cleanup is unavailable.

## Patch Rationale
`rmdir` matches the object type created by `mkdtemp` and fixes only the broken failure-path cleanup behavior. It preserves the existing success-path design where the helper removes the directory tree during normal handler disposal.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/handler/configurator/fastcgi.c b/lib/handler/configurator/fastcgi.c
--- a/lib/handler/configurator/fastcgi.c
+++ b/lib/handler/configurator/fastcgi.c
@@ -284,7 +284,7 @@ Exit:
     if (sockname[0] != '\0')
         unlink(sockname);
     if (dirname[0] != '\0')
-        unlink(dirname);
+        rmdir(dirname);
     free_argv(argv);
     return NULL;
 }
```