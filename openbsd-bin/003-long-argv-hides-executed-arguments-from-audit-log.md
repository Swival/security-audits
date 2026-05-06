# Long argv hides executed arguments from audit log

## Classification

Repudiation, low severity, certain confidence.

## Affected Locations

- `doas/doas.c:437`

## Summary

`doas` builds a fixed-size `cmdline[LINE_MAX]` string for audit logging, explicitly tolerated truncation, and then authorized and executed the original full `argv`. A permitted local user could place security-relevant arguments after the logging buffer limit so they are executed but absent from the successful `doas` audit record.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Attacker is a lower-privileged local user.
- Attacker has a matching `doas` rule for the invoked command.
- The matching rule logs successful execution, meaning it does not use `nolog`.
- The rule permits the supplied full argument vector, commonly a `cmd` rule without an `args` restriction.
- The attacker can provide enough earlier argument text to exceed `LINE_MAX` before trailing security-relevant arguments.

## Proof

The issue was reproduced.

The vulnerable flow is:

- `doas/doas.c:405` builds `cmdline` only for logging.
- The original code used `strlcpy()` and `strlcat()` into `cmdline[LINE_MAX]`.
- The original comment stated truncation was acceptable: `cmdline is used only for logging, no need to abort on truncate`.
- `doas/doas.c:418` calls `permit()` with `(const char **)argv + 1`, so authorization checks the original argument vector, not the truncated display string.
- `doas/doas.c:478` logs successful execution with `cmdline`.
- `doas/doas.c:493` executes `execvpe(cmd, argv, envp)` with the original full `argv`.

Therefore, when the argument display string reaches `LINE_MAX`, the syslog message records only the truncated prefix while the executed command receives all trailing arguments.

## Why This Is A Real Bug

The audit log is intended to record what command a user successfully ran through `doas`. Before the patch, the log string and executed argument vector could diverge: the log used a lossy fixed-size rendering, while execution used the complete `argv`.

This creates a concrete repudiation gap. A user can run a command with trailing arguments that affect behavior, while the audit record omits those arguments. The behavior does not depend on undefined behavior or a crash; it follows directly from intentional truncation of `cmdline` and later execution of the unmodified `argv`.

## Fix Requirement

`doas` must either:

- log the full argument vector losslessly, or
- reject command invocations when the audit logging representation would be truncated.

The patched behavior implements rejection on truncation.

## Patch Rationale

The patch changes `cmdline` construction from best-effort truncation to strict validation:

- `strlcpy(cmdline, argv[0], sizeof(cmdline))` is checked.
- Each `strlcat(cmdline, " ", sizeof(cmdline))` is checked.
- Each `strlcat(cmdline, argv[i], sizeof(cmdline))` is checked.
- Any truncation attempt terminates with `errx(1, "command line too long")`.

This preserves the existing single-string audit format while guaranteeing that any successfully logged and executed command has a complete `cmdline` representation.

## Residual Risk

None

## Patch

```diff
diff --git a/doas/doas.c b/doas/doas.c
index 3999b2e..a63af7b 100644
--- a/doas/doas.c
+++ b/doas/doas.c
@@ -405,13 +405,14 @@ main(int argc, char **argv)
 
 	parseconfig("/etc/doas.conf", 1);
 
-	/* cmdline is used only for logging, no need to abort on truncate */
-	(void)strlcpy(cmdline, argv[0], sizeof(cmdline));
+	/* cmdline is used for audit logging; reject anything truncated. */
+	if (strlcpy(cmdline, argv[0], sizeof(cmdline)) >= sizeof(cmdline))
+		errx(1, "command line too long");
 	for (i = 1; i < argc; i++) {
 		if (strlcat(cmdline, " ", sizeof(cmdline)) >= sizeof(cmdline))
-			break;
+			errx(1, "command line too long");
 		if (strlcat(cmdline, argv[i], sizeof(cmdline)) >= sizeof(cmdline))
-			break;
+			errx(1, "command line too long");
 	}
 
 	cmd = argv[0];
```