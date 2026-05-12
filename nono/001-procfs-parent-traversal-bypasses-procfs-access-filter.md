# procfs parent traversal bypasses procfs access filter

## Classification

security_control_failure, high severity, confidence: certain

## Affected Locations

- `crates/nono-cli/src/exec_strategy.rs:2965` (`validate_procfs_access`)
- `crates/nono-cli/src/exec_strategy.rs:3080` (`open_path_for_access`)

## Summary

A sandboxed child can request a supervisor-opened procfs path containing `..` components and bypass the supervisor's procfs access filter. The pre-canonicalization procfs check validates the unresolved string, accepts the child PID prefix, and misses that canonicalization later resolves the path to a foreign procfs target such as `/proc/1/maps`.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Approval is granted for the capability request.
- The target foreign procfs file is readable by the supervisor process.
- The child can request a procfs path with parent-directory traversal.

## Proof

A request path such as:

```text
/proc/<child>/task/<tid>/../../../1/maps
```

passes through `handle_supervisor_message`, which calls `open_path_for_access` for granted requests with `ProcfsAccessContext` set to the child process.

`open_path_for_access` first rewrites procfs self references, then calls `validate_procfs_access` before canonicalization. The vulnerable validation string-splits the unresolved path. For the traversal path:

- `pid_component == <child>`
- `sensitive_component == ".."`

Because the PID matches the child and `..` is not in the blocked procfs component list, validation returns `Ok(())`.

`open_path_for_access` then canonicalizes the already-approved path. The kernel resolves the traversal to a foreign target such as:

```text
/proc/1/maps
```

The supervisor then opens that canonical target with `open_canonical_path_no_symlinks` and returns the file descriptor to the sandboxed child via SCM_RIGHTS.

## Why This Is A Real Bug

The procfs filter intends to prevent access to foreign process procfs files and sensitive procfs entries. It fails because authorization is performed on an unresolved path while the actual open is performed after canonicalization. Parent traversal changes the procfs PID after validation, so the supervisor can return an fd for a foreign process that policy should have denied.

The impact is information disclosure and procfs policy bypass for any parent-readable foreign procfs target. `/proc/1/maps` is one example and depends on host permissions; the bypass is not limited to PID 1.

## Fix Requirement

Procfs paths must not be allowed to contain parent-directory traversal before authorization, or procfs access checks must be repeated after canonicalization. The fix must ensure a path validated as child-owned procfs cannot resolve to another PID's procfs tree.

## Patch Rationale

The patch rejects any `..` component in procfs paths before PID and sensitive-component validation. This closes the bypass at the same point where procfs provenance is still visible, before `canonicalize()` can erase the original traversal structure.

This is sufficient for the reproduced issue because the exploit requires `Component::ParentDir` to escape from `/proc/<child>/task/<tid>` into a foreign PID directory.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/exec_strategy.rs b/crates/nono-cli/src/exec_strategy.rs
index 64ca700..05eb7a8 100644
--- a/crates/nono-cli/src/exec_strategy.rs
+++ b/crates/nono-cli/src/exec_strategy.rs
@@ -2979,6 +2979,13 @@ fn validate_procfs_access(
     let allowed_pid = procfs_context.map(|ctx| ctx.process_pid.to_string());
     let components: Vec<&str> = suffix.split('/').collect();
 
+    if components.iter().any(|component| *component == "..") {
+        return Err(OpenPathError::policy_blocked(format!(
+            "Access to {} is blocked by policy",
+            resolved_path.display(),
+        )));
+    }
+
     if components.is_empty() || !components[0].chars().all(|c| c.is_ascii_digit()) {
         return Ok(());
     }
```