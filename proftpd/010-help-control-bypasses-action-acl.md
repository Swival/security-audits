# help control bypasses action ACL

## Classification

Authorization bypass, medium severity.

## Affected Locations

`modules/mod_ctrls.c:662`

## Summary

The `help` controls handler executes without checking the configured action ACL for `help`. A local controls socket client that is allowed by the socket ACL can request `help` and receive registered-control descriptions even when `ControlsACLs help deny ...` should deny that action.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `ControlsEngine` is enabled.
- The attacker can connect to the local controls socket.
- The controls socket ACL permits the attacker connection.
- The `help` action ACL denies the attacker, e.g. `ControlsACLs help deny user <attacker>`.

## Proof

A local controls client sends a `help` request via `ftpdctl help` or an equivalent `pr_ctrls_send_request()` call.

Request flow:

- `modules/mod_ctrls.c:777` calls `pr_run_ctrls(NULL, NULL)`.
- `src/ctrls.c:717` and `src/ctrls.c:775` resolve the requested action and mark it requested.
- `src/ctrls.c:1776` dispatches requested controls without performing per-action ACL checks.
- `src/ctrls.c:1842` calls the registered callback.
- `modules/mod_ctrls.c:796` enters `ctrls_handle_help()`.
- `modules/mod_ctrls.c:808` calls `pr_get_registered_actions(ctrl, CTRLS_GET_DESC)` and returns registered-control descriptions.
- Unlike `insctrl`, `lsctrl`, and `rmctrl`, `ctrls_handle_help()` does not call `pr_ctrls_check_acl()` before returning data.

Result: a denied user receives the `help` output instead of `PR_CTRLS_STATUS_ACCESS_DENIED`.

## Why This Is A Real Bug

`ControlsACLs` accepts ACL configuration for the `help` action via `set_ctrlsacls()` and `pr_ctrls_set_module_acls2()`. The action is registered in `ctrls_acttab`, so administrators can explicitly deny it. However, enforcement is handler-local, and `pr_run_ctrls()` does not perform the action ACL check centrally. Since `ctrls_handle_help()` omits the check, the configured deny rule is bypassed.

The neighboring built-in handlers demonstrate the intended authorization model:

- `ctrls_handle_insctrl()` checks `pr_ctrls_check_acl(ctrl, ctrls_acttab, "insctrl")`.
- `ctrls_handle_lsctrl()` checks `pr_ctrls_check_acl(ctrl, ctrls_acttab, "lsctrl")`.
- `ctrls_handle_rmctrl()` checks `pr_ctrls_check_acl(ctrl, ctrls_acttab, "rmctrl")`.

`help` should follow the same pattern.

## Fix Requirement

Before processing the `help` request or returning registered action descriptions, `ctrls_handle_help()` must call:

```c
pr_ctrls_check_acl(ctrl, ctrls_acttab, "help")
```

If the check does not return `TRUE`, the handler must add an `access denied` response and return `PR_CTRLS_STATUS_ACCESS_DENIED`.

## Patch Rationale

The patch adds the missing action ACL check at the start of `ctrls_handle_help()`, matching the established authorization pattern used by `insctrl`, `lsctrl`, and `rmctrl`.

This ensures that a denied `help` action stops before `pr_get_registered_actions(ctrl, CTRLS_GET_DESC)` can disclose registered-control descriptions.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/mod_ctrls.c b/modules/mod_ctrls.c
index 392307f9a..45f963327 100644
--- a/modules/mod_ctrls.c
+++ b/modules/mod_ctrls.c
@@ -800,6 +800,14 @@ static int ctrls_handle_help(pr_ctrls_t *ctrl, int reqargc,
    * response, including the module in which they appear.
    */
 
+  /* Check the help ACL */
+  if (pr_ctrls_check_acl(ctrl, ctrls_acttab, "help") != TRUE) {
+
+    /* Access denied */
+    pr_ctrls_add_response(ctrl, "access denied");
+    return PR_CTRLS_STATUS_ACCESS_DENIED;
+  }
+
   if (reqargc != 0) {
     pr_ctrls_add_response(ctrl, "wrong number of parameters");
     return PR_CTRLS_STATUS_WRONG_PARAMETERS;
```