# Newline In Script Path Injects Crontab Entries

## Classification

Injection, CWE-78/CWE-77 adjacent command or cron entry injection.

Severity: medium.

Confidence: certain.

## Affected Locations

`src/runtime/api/cron.rs:389`

`src/runtime/api/cron.rs:700`

`src/runtime/api/cron.rs:714`

## Summary

OS-level `Bun.cron(path, schedule, title)` accepted resolved script paths containing CR/LF. On non-macOS Unix paths, `process_crontab_and_install` embedded `abs_path` directly into a generated crontab line. A newline in the path terminated Bun's intended command line and let attacker-controlled trailing bytes become additional crontab entries installed for the same user.

The patch rejects `\n` and `\r` in `abs_path` before any crontab content is generated.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was independently reproduced and patched from the provided source and reproducer evidence.

## Preconditions

Linux/Unix OS-level Bun.cron registration reaches crontab installation.

An attacker can influence the resolved script path passed to `Bun.cron`.

## Proof

Before the patch, `cron_register` resolved the caller-provided path and only rejected single quotes and percent signs.

`process_crontab_and_install` then wrote the resolved path into the crontab entry:

```cron
# bun-cron: t
* * * * * '/usr/bin/bun' run --cron-title=t --cron-period='* * * * *' '<path>'
```

A path containing:

```text
/tmp/prefix
* * * * * /bin/sh -c "touch /tmp/buncron_poc" #
```

produced crontab content shaped like:

```cron
# bun-cron: t
* * * * * '/usr/bin/bun' run --cron-title=t --cron-period='* * * * *' '/tmp/prefix
* * * * * /bin/sh -c "touch /tmp/buncron_poc" # '
```

The injected line is syntactically valid because the shell comment marker consumes Bun's trailing quote. The reproduced generated form was accepted by local `crontab -n` syntax checking.

## Why This Is A Real Bug

The vulnerable value is written to a line-oriented crontab format. Single-quote validation prevents ordinary shell quoting breaks, and percent validation prevents cron `%` newline semantics, but neither protects against literal CR/LF bytes.

Because `crontab tmp_path` installs the generated file, a newline in `abs_path` directly changes the number and content of installed cron entries. The impact is arbitrary same-user cron commands and persistence outside Bun's intended single job registration.

## Fix Requirement

Reject carriage return and line feed bytes in resolved OS-level cron script paths before writing crontab entries.

The validation must happen before `CronRegisterJob` stores `abs_path` and before `process_crontab_and_install` formats the crontab file.

## Patch Rationale

The existing validation loop in `cron_register` is the correct enforcement point because it already rejects path bytes that cannot be safely represented in cron-backed registrations.

Adding CR/LF rejection there ensures the same `abs_path` cannot later reach the non-macOS crontab writer with line separators. The error is explicit and preserves existing behavior for safe paths.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/api/cron.rs b/src/runtime/api/cron.rs
index 31a8c944ee..0e03cba31c 100644
--- a/src/runtime/api/cron.rs
+++ b/src/runtime/api/cron.rs
@@ -700,8 +700,9 @@ pub fn cron_register(global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSV
         }
     };
 
-    // Validate path has no single quotes (shell escaping in crontab) or
-    // percent signs (cron interprets % as newline before the shell sees it)
+    // Validate path has no single quotes (shell escaping in crontab),
+    // percent signs (cron interprets % as newline before the shell sees it),
+    // or line breaks (which would create additional crontab entries).
     for &c in abs_path.as_bytes() {
         if c == b'\'' {
             return Err(
@@ -713,6 +714,11 @@ pub fn cron_register(global: &JSGlobalObject, frame: &CallFrame) -> JsResult<JSV
                 "Path must not contain percent signs (cron interprets % as newline)"
             )));
         }
+        if c == b'\n' || c == b'\r' {
+            return Err(global.throw_invalid_arguments(format_args!(
+                "Path must not contain line breaks"
+            )));
+        }
     }
 
     let bun_exe = match bun_core::self_exe_path() {
```