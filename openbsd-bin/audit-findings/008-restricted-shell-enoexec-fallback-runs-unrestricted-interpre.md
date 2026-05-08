# restricted shell ENOEXEC fallback runs unrestricted interpreter

## Classification

High severity sandbox escape.

Confidence: certain.

## Affected Locations

`bin/ksh/exec.c:553`

Patched location: `bin/ksh/exec.c:380`

## Summary

Restricted `ksh` blocks direct slash-containing command execution and other restricted operations, but its `ENOEXEC` fallback path executes text files through an unrestricted interpreter. A user who can run a PATH-reachable executable text file without a kernel-recognized interpreter can escape restricted shell controls.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- User is running in restricted `ksh`.
- User can execute a text file that lacks a kernel-recognized interpreter.
- The text file is reachable through command lookup, such as via `PATH`.
- `execve()` on that file fails with `ENOEXEC`.

## Proof

`comexec()` blocks explicit slash-containing command names in restricted mode before command lookup:

`bin/ksh/exec.c:533`

For executable commands, `comexec()` builds a `TEXEC` node and calls `exchild()`:

`bin/ksh/exec.c:553`

The `TEXEC` case calls `execve()` on the resolved command path:

`bin/ksh/exec.c:376`

If `execve()` fails with `ENOEXEC`, the old code calls `scriptexec()` unconditionally:

`bin/ksh/exec.c:380`

`scriptexec()` chooses `EXECSHELL` or `_PATH_BSHELL`, rewrites `argv` to execute the text file as a script, and calls `execve()` on that shell:

`bin/ksh/exec.c:705`

`bin/ksh/exec.c:710`

`bin/ksh/exec.c:713`

`bin/ksh/exec.c:716`

`bin/ksh/exec.c:719`

There is no `Flag(FRESTRICTED)` check in that fallback and no forced restricted-shell invocation, so the fallback interpreter can run without the restricted checks that applied to the original shell.

## Why This Is A Real Bug

Restricted mode is intended to constrain the user by disabling operations such as `cd`, slash-containing command names, restricted variable changes, and creating redirections.

The reproduced path bypasses those controls because the restricted shell validates the original command lookup, then delegates `ENOEXEC` text-file execution to another interpreter without preserving restricted mode. The resulting script can perform operations the restricted shell would have rejected directly.

The caveat where an inherited `SHELL` value may cause `ksh`/`sh` to re-enter restricted mode does not eliminate the bug. `EXECSHELL` is not protected by restricted mode, and `scriptexec()` accepts absolute interpreter paths through `search()`.

## Fix Requirement

In restricted mode, the `ENOEXEC` fallback must not run an unrestricted interpreter. It must either reject the fallback or explicitly execute a restricted shell mode.

## Patch Rationale

The patch rejects the `ENOEXEC` fallback while `Flag(FRESTRICTED)` is set:

```diff
if (errno == ENOEXEC) {
	if (Flag(FRESTRICTED))
		errorf("%s: restricted", s);
	scriptexec(t, ap);
}
```

This preserves normal `ENOEXEC` script fallback behavior for unrestricted shells while preventing restricted shells from delegating execution to an unconstrained interpreter.

The fix is placed immediately after the failed `execve()` and before `scriptexec()`, which is the exact trust boundary where the shell would otherwise leave restricted enforcement.

## Residual Risk

None

## Patch

`008-restricted-shell-enoexec-fallback-runs-unrestricted-interpre.patch`

```diff
diff --git a/bin/ksh/exec.c b/bin/ksh/exec.c
index 69a1cb9..b3975b6 100644
--- a/bin/ksh/exec.c
+++ b/bin/ksh/exec.c
@@ -380,9 +380,11 @@ execute(struct op *volatile t,
 		restoresigs();
 		cleanup_proc_env();
 		execve(t->str, t->args, ap);
-		if (errno == ENOEXEC)
+		if (errno == ENOEXEC) {
+			if (Flag(FRESTRICTED))
+				errorf("%s: restricted", s);
 			scriptexec(t, ap);
-		else
+		} else
 			errorf("%s: %s", s, strerror(errno));
 	}
     Break:
```