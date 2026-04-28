# Uninitialized Application Name Passed To CreateProcess

## Classification

Invariant violation. Severity: low. Confidence: certain.

## Affected Locations

`support/win32/wintty.c:266`

## Summary

In the Windows service relaunch path, `appbuff` is a stack buffer intended to hold the current executable path. The code assigns `appname = appbuff` only when `GetModuleFileName` fails, leaving `appbuff` uninitialized. `CreateProcess` then receives an indeterminate `lpApplicationName` string.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

- The default `#else` service relaunch implementation is compiled.
- The process is running in the service branch, so `isservice` is true.
- `GetModuleFileName(NULL, appbuff, sizeof(appbuff))` returns `0`.

## Proof

- `appbuff` is declared as a stack buffer in the service relaunch branch at `support/win32/wintty.c:245`.
- `appbuff` is not initialized before the `GetModuleFileName` call.
- The check is inverted: when `GetModuleFileName` fails, the code assigns `appname = appbuff`.
- `CreateProcess(appname, cmdline, ...)` receives `appname` as `lpApplicationName`.
- Under the failure condition, `appname` points to indeterminate stack bytes, not a guaranteed NUL-terminated executable path.

## Why This Is A Real Bug

`CreateProcess` requires `lpApplicationName` to be either `NULL` or a valid NUL-terminated string. Passing an uninitialized stack buffer violates that API invariant. This can cause unpredictable relaunch failure or cause Windows to interpret arbitrary stack bytes as an executable path. The path is reachable whenever the service relaunch branch executes and `GetModuleFileName` fails.

## Fix Requirement

Assign `appname = appbuff` only when `GetModuleFileName` succeeds. On failure, leave `appname` as `NULL` so `CreateProcess` uses the command line parsing behavior, or fail cleanly.

## Patch Rationale

The patch corrects the inverted success check. `GetModuleFileName` returns nonzero on success and zero on failure, so `appname` is now set only when `appbuff` contains a valid module path.

## Residual Risk

None

## Patch

```diff
diff --git a/support/win32/wintty.c b/support/win32/wintty.c
index 684ce5b..0b914c5 100644
--- a/support/win32/wintty.c
+++ b/support/win32/wintty.c
@@ -246,7 +246,7 @@ int main(int argc, char** argv)
         char *appname = NULL;
         char *cmdline = GetCommandLine();
 
-        if (!GetModuleFileName(NULL, appbuff, sizeof(appbuff))) {
+        if (GetModuleFileName(NULL, appbuff, sizeof(appbuff))) {
             appname = appbuff;
         }
```