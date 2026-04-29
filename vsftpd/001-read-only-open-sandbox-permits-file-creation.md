# Read-Only Open Sandbox Permits File Creation

## Classification

security_control_failure; severity high; confidence certain.

## Affected Locations

`ptracesandbox.c:805`

## Summary

`ptrace_sandbox_permit_open(..., 0)` installs `validate_open_readonly` for `__NR_open`, but the validator only enforced the access mode bits. Because `O_CREAT` is not part of `O_ACCMODE`, a sandboxed tracee could call `open("newfile", O_RDONLY | O_CREAT, 0600)` and create a filesystem entry despite a read-only open policy.

## Provenance

Reported and reproduced from scanner output attributed to Swival Security Scanner: https://swival.dev

## Preconditions

- The ptrace sandbox is active on the supported Linux i386 path.
- The policy permits `open` with `writeable` set to `0`.
- The attacker controls a sandboxed tracee syscall to `open`.

## Proof

- `ptrace_sandbox_permit_open(..., 0)` installs `validate_open_readonly` as the `__NR_open` validator.
- `validate_open_readonly` first calls `validate_open_default`.
- `validate_open_default` rejects only `O_ASYNC`, `O_DIRECT`, and `O_SYNC`.
- `validate_open_readonly` then checks only `(arg2 & O_ACCMODE) != O_RDONLY`.
- `O_RDONLY | O_CREAT` passes that check because `O_CREAT` is outside `O_ACCMODE`.
- `get_action` treats validator return `0` as allow and continues the traced syscall.
- Result: `open("newfile", O_RDONLY | O_CREAT, 0600)` creates a new filesystem entry under a read-only open policy.

## Why This Is A Real Bug

This is the sandbox syscall access-control layer. The named read-only open control deterministically allows a mutating open flag. File creation changes filesystem state, so allowing `O_CREAT` violates the intended read-only policy and causes a sandbox integrity failure.

## Fix Requirement

Reject mutating flags in the read-only open validator, including at least `O_CREAT`, `O_TRUNC`, and `O_APPEND`, while continuing to require `O_RDONLY` access mode.

## Patch Rationale

The patch extends `validate_open_readonly` so a call is denied when either the access mode is not `O_RDONLY` or any mutating open flag is present. This preserves legitimate read-only opens while blocking creation, truncation, and append-oriented mutation attempts that contradict the read-only policy.

## Residual Risk

None

## Patch

```diff
diff --git a/ptracesandbox.c b/ptracesandbox.c
index 37efd5a..a5b84d4 100644
--- a/ptracesandbox.c
+++ b/ptracesandbox.c
@@ -804,7 +804,8 @@ validate_open_readonly(struct pt_sandbox* p_sandbox, void* p_arg)
   {
     return ret;
   }
-  if ((arg2 & O_ACCMODE) != O_RDONLY)
+  if ((arg2 & O_ACCMODE) != O_RDONLY ||
+      (arg2 & (O_CREAT | O_TRUNC | O_APPEND)))
   {
     return -1;
   }
```