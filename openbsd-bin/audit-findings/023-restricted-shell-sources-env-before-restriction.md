# Restricted Shell Sources ENV Before Restriction

## Classification

security_control_failure, high severity.

## Affected Locations

`bin/ksh/main.c:430`

## Summary

Interactive restricted shells invoked as `rsh`, `rksh`, `rpdksh`, or `pdrksh` executed attacker-controlled `$ENV` startup files before restricted mode was applied. Because `FRESTRICTED` was temporarily cleared during startup processing, `$ENV` could run unrestricted shell commands, including restricted-forbidden operations such as executing `/bin/sh`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Interactive non-privileged shell.
- Shell invoked as `rsh`, `rksh`, `rpdksh`, or `pdrksh`.
- Attacker controls `ENV` or can cause it to name an attacker-controlled startup script.

## Proof

`main()` saved the current restricted flag, then cleared it before profile and `$ENV` processing:

```c
restricted = Flag(FRESTRICTED);
Flag(FRESTRICTED) = 0;
```

For non-privileged interactive shells, startup then read `ENV`, expanded it, and executed the named file:

```c
env_file = str_val(global("ENV"));
env_file = substitute(env_file, DOTILDE);
if (*env_file != '\0')
	include(env_file, 0, NULL, 1);
```

`include()` opens the file and executes it as shell code via `shell(s, false)` at `bin/ksh/main.c:523`.

Only after `$ENV` returned did `main()` detect restricted invocation and mark `PATH`, `ENV`, and `SHELL` readonly before restoring `Flag(FRESTRICTED) = 1`.

A pty proof-of-concept confirmed that invoking the shell as `rksh` with `ENV=/tmp/rksh_env_poc` executed the ENV file before restriction. The ENV file changed directory to `/`, created files via redirection, and executed `/bin/sh -i`.

## Why This Is A Real Bug

Restricted shell confinement is supposed to apply before user-controlled startup code can execute. In the vulnerable flow, the confinement decision was delayed until after `$ENV` execution.

The bypass is security-relevant because restricted-command checks depend on `Flag(FRESTRICTED)`. For example, the slash-containing command restriction in `bin/ksh/exec.c:533` only applies when `Flag(FRESTRICTED)` is set. During `$ENV` startup execution, it was cleared, so `exec /bin/sh -i` bypassed the restricted shell policy.

## Fix Requirement

Determine restricted mode before processing `$ENV`, and prevent attacker-controlled `$ENV` startup files from executing when the shell is restricted.

## Patch Rationale

The patch computes `restricted` before profile and `$ENV` processing by checking both the existing `FRESTRICTED` flag and restricted shell names from `argv[0]` or `$SHELL`:

```c
restricted = Flag(FRESTRICTED) || is_restricted(argv[0]) ||
    is_restricted(str_val(global("SHELL")));
```

It then skips `$ENV` processing for restricted shells:

```c
else if (Flag(FTALKING) && !restricted) {
```

This preserves ordinary interactive `$ENV` behavior for unrestricted shells while ensuring restricted shells cannot execute attacker-controlled startup scripts before confinement is applied.

## Residual Risk

None

## Patch

```diff
diff --git a/bin/ksh/main.c b/bin/ksh/main.c
index b011b22..e55e227 100644
--- a/bin/ksh/main.c
+++ b/bin/ksh/main.c
@@ -393,7 +393,8 @@ main(int argc, char *argv[])
 	getopts_reset(1);
 
 	/* Disable during .profile/ENV reading */
-	restricted = Flag(FRESTRICTED);
+	restricted = Flag(FRESTRICTED) || is_restricted(argv[0]) ||
+	    is_restricted(str_val(global("SHELL")));
 	Flag(FRESTRICTED) = 0;
 	errexit = Flag(FERREXIT);
 	Flag(FERREXIT) = 0;
@@ -412,7 +413,7 @@ main(int argc, char *argv[])
 
 	if (Flag(FPRIVILEGED))
 		include("/etc/suid_profile", 0, NULL, 1);
-	else if (Flag(FTALKING)) {
+	else if (Flag(FTALKING) && !restricted) {
 		char *env_file;
 
 		/* include $ENV */
```