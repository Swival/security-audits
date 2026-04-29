# Mixed Privilege Nesting Retains Root EUID

## Classification

security_control_failure, high severity

## Affected Locations

`src/privs.c:282`

## Summary

`pr_privs_relinquish()` fails open when root and user privilege scopes are active at the same time. A caller can enter `PRIVS_USER`, then `PRIVS_ROOT`, then call `PRIVS_RELINQUISH`; the function returns success from the mixed-nesting branch without decrementing either counter or dropping effective UID from root.

## Provenance

Reported and reproduced from Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

- Daemon started as root.
- ID switching is enabled.
- Privilege switching syscalls succeed.
- A caller can trigger the privilege switcher sequence `PRIVS_USER`, `PRIVS_ROOT`, `PRIVS_RELINQUISH`.

## Proof

`pr_privs_user()` increments `user_privs` and switches effective UID to `session.login_uid`.

`pr_privs_root()` does not reject an active `user_privs` scope. It checks only `root_privs > 0`, increments `root_privs`, and switches effective IDs to root.

After this sequence:

```text
PRIVS_USER
PRIVS_ROOT
```

the internal state is:

```text
user_privs == 1
root_privs == 1
effective UID == PR_ROOT_UID
```

Calling `PRIVS_RELINQUISH` then reaches the mixed-count branch:

```c
if (root_privs + user_privs > 1) {
  pr_trace_msg(trace_channel, 9,
    "root privs count = %u, user privs count = %u, ignoring PRIVS_RELINQUISH",
    root_privs, user_privs);
  return 0;
}
```

Because this branch returns before decrementing `root_privs` or `user_privs`, and before calling `seteuid(session.uid)`, the process remains root-effective while the function reports success.

The counters remain `1 + 1`, so later `PRIVS_RELINQUISH` calls also take the same early-return path and cannot unwind the privilege state.

## Why This Is A Real Bug

`pr_privs_relinquish()` is the drop-root decision point for this privilege control. Under the stated preconditions, a reachable nested sequence causes it to return success while retaining root effective UID.

This is not only incorrect accounting. The incorrect accounting directly prevents the UID drop path from executing and leaves the process stuck with root effective privileges.

## Fix Requirement

The mixed-nesting path must unwind the active privilege counter before returning. If the relinquish operation removes the active root scope, the process must no longer retain root effective UID and must transition to the appropriate remaining privilege state.

## Patch Rationale

The patch changes the `root_privs + user_privs > 1` branch from an unconditional successful no-op into an active unwind path.

When the current effective UID is root and `root_privs > 0`, the patch decrements the mixed nesting counters and invokes `pr_privs_user(file, lineno)` so the remaining user privilege scope is restored instead of leaving the process root-effective.

When the current effective UID is not root and `user_privs > 0`, the patch decrements the mixed nesting counters and invokes `pr_privs_root(file, lineno)` so the remaining root scope is restored consistently.

This prevents the mixed state from becoming permanently stuck at `root_privs == 1` and `user_privs == 1`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/privs.c b/src/privs.c
index 4212febf8..8afbfc79c 100644
--- a/src/privs.c
+++ b/src/privs.c
@@ -282,8 +282,22 @@ int pr_privs_relinquish(const char *file, int lineno) {
    */
   if (root_privs + user_privs > 1) {
     pr_trace_msg(trace_channel, 9,
-      "root privs count = %u, user privs count = %u, ignoring PRIVS_RELINQUISH",
+      "root privs count = %u, user privs count = %u, honoring PRIVS_RELINQUISH",
       root_privs, user_privs);
+
+    if (geteuid() == PR_ROOT_UID &&
+        root_privs > 0) {
+      root_privs--;
+      user_privs--;
+      return pr_privs_user(file, lineno);
+    }
+
+    if (user_privs > 0) {
+      user_privs--;
+      root_privs--;
+      return pr_privs_root(file, lineno);
+    }
+
     return 0;
   }
```