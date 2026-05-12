# Audit Path Terminal Escape Injection

## Classification

Log injection / terminal escape injection.

Severity: Medium.

Confidence: Certain.

## Affected Locations

`crates/nono-cli/src/audit_commands.rs:333`

## Summary

`nono audit show` printed snapshot change paths directly to the terminal with `change.path.display()`. Snapshot paths can originate from filenames created by a sandboxed child process. A crafted filename containing carriage returns, control bytes, or ANSI escape sequences could manipulate the operator's terminal output when the audit trail is viewed.

The patch sanitizes rendered snapshot change paths before printing them.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A sandboxed child process can create tracked files or directories with crafted names.
- The crafted path is recorded as a snapshot change.
- A user runs `nono audit show` for that session in a terminal.

## Proof

The vulnerable path is in `cmd_show`:

```rust
for change in &changes {
    let symbol = change_symbol(&change.change_type);
    eprintln!("        {} {}", symbol, change.path.display());
}
```

`SnapshotManager::load_changes_from` loads snapshot changes, then `cmd_show` renders each `change.path.display()` directly in terminal output.

A child process can create a tracked filename containing terminal control sequences, such as carriage return plus CSI clear-line text. That filename becomes legitimate snapshot data and is later emitted raw by `nono audit show`.

The same file already treats network audit fields as untrusted and calls `sanitize_for_terminal` before display, showing the intended terminal-safety boundary was missing for snapshot paths.

## Why This Is A Real Bug

This is attacker-controlled terminal output injection. The attacker does not need to modify audit rendering code or audit metadata directly; they only need to create a filename that is captured in snapshot changes.

When an operator views the audit session, the terminal may interpret embedded control sequences and allow the displayed audit trail to be forged, rewritten, cleared, or partially hidden.

## Fix Requirement

All untrusted text printed to an interactive terminal must be sanitized before display.

Specifically, snapshot change paths rendered by `nono audit show` must pass through `sanitize_for_terminal` before being sent to `eprintln!`.

## Patch Rationale

The patch converts the rendered path to a string and applies the existing terminal sanitizer:

```rust
sanitize_for_terminal(&change.path.display().to_string())
```

This preserves normal path display while stripping ANSI escape sequences and replacing control characters before terminal output.

The fix is narrow and consistent with existing handling of network audit fields in the same command.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/audit_commands.rs b/crates/nono-cli/src/audit_commands.rs
index 8338836..190b69a 100644
--- a/crates/nono-cli/src/audit_commands.rs
+++ b/crates/nono-cli/src/audit_commands.rs
@@ -330,7 +330,11 @@ fn cmd_show(args: AuditShowArgs) -> Result<()> {
 
             for change in &changes {
                 let symbol = change_symbol(&change.change_type);
-                eprintln!("        {} {}", symbol, change.path.display());
+                eprintln!(
+                    "        {} {}",
+                    symbol,
+                    sanitize_for_terminal(&change.path.display().to_string())
+                );
             }
         }
     }
```