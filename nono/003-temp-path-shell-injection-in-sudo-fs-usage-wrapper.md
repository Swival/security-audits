# Temp Path Shell Injection In Sudo fs_usage Wrapper

## Classification

Command execution, high severity, confidence certain.

## Affected Locations

`crates/nono-cli/src/learn.rs:546`

## Summary

macOS learn mode created `NamedTempFile` paths and interpolated them into a `sudo bash -c` command using single quotes. An attacker controlling `TMPDIR` could include a single quote and shell syntax in the temp path, causing root command execution during shell expansion after sudo credentials were acquired.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The target platform is macOS.
- The lower-privileged local attacker invokes learn mode.
- macOS learn mode reaches `acquire_sudo()` successfully.
- The attacker controls `TMPDIR`, influencing `tempfile::NamedTempFile::new()` path selection.

## Proof

The vulnerable code built a root shell command with unescaped temp paths:

```rust
format!(
    "exec fs_usage -w -f filesys -f pathname {} > '{}' 2> '{}'",
    cmd_name,
    fs_usage_out_path.display(),
    fs_usage_err_path.display()
)
```

An attacker-controlled temp directory such as:

```text
/tmp/nono'$(touch /tmp/root-owned)'
```

produces a shell redirection word equivalent to:

```sh
> '/tmp/nono'$(touch /tmp/root-owned)'/.tmpXXXX'
```

`$(touch /tmp/root-owned)` executes during shell expansion inside the root `sudo bash` process before `fs_usage` is exec'd.

## Why This Is A Real Bug

The path values are attacker-influenced through `TMPDIR`, are inserted into shell syntax without escaping, and are evaluated by `bash -c` running under `sudo`. Command substitution inside the redirection operand executes before `exec fs_usage`, so exploitation does not depend on `fs_usage` failing or returning.

## Fix Requirement

Do not pass attacker-influenced paths through `bash -c`. Spawn `fs_usage` directly under `sudo` and attach stdout/stderr using `Stdio` file handles, or otherwise apply correct shell escaping. Avoiding the shell is the required safer fix.

## Patch Rationale

The patch removes `bash -c` and shell-level redirection entirely. It reopens the temporary files as file handles and passes them directly to `.stdout()` and `.stderr()`, then invokes:

```rust
sudo /usr/bin/fs_usage -w -f filesys -f pathname <cmd_name>
```

This preserves buffered-output behavior while eliminating shell parsing of temp paths.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/learn.rs b/crates/nono-cli/src/learn.rs
index 9bf154b..7cc33e6 100644
--- a/crates/nono-cli/src/learn.rs
+++ b/crates/nono-cli/src/learn.rs
@@ -529,12 +529,15 @@ fn run_fs_usage_and_nettop(
     // fs_usage fully buffers stdout when writing to a pipe, so trace data
     // accumulates in an internal buffer and is lost when fs_usage is killed
     // via SIGTERM. To work around this, we redirect output to a temp file
-    // via shell-level redirection inside sudo, then read the file after
-    // fs_usage exits.
+    // by redirecting stdout/stderr directly to temp files, then read the
+    // files after fs_usage exits.
     let fs_usage_outfile = tempfile::NamedTempFile::new().map_err(|e| {
         NonoError::LearnError(format!("Failed to create temp file for fs_usage: {e}"))
     })?;
     let fs_usage_out_path = fs_usage_outfile.path().to_path_buf();
+    let fs_usage_stdout = fs_usage_outfile.reopen().map_err(|e| {
+        NonoError::LearnError(format!("Failed to reopen temp file for fs_usage: {e}"))
+    })?;
 
     let fs_usage_errfile = tempfile::NamedTempFile::new().map_err(|e| {
         NonoError::LearnError(format!(
@@ -542,21 +545,17 @@ fn run_fs_usage_and_nettop(
         ))
     })?;
     let fs_usage_err_path = fs_usage_errfile.path().to_path_buf();
+    let fs_usage_stderr = fs_usage_errfile.reopen().map_err(|e| {
+        NonoError::LearnError(format!(
+            "Failed to reopen temp file for fs_usage stderr: {e}"
+        ))
+    })?;
 
     let mut fs_usage = Command::new("sudo")
-        .args([
-            "bash",
-            "-c",
-            &format!(
-                "exec fs_usage -w -f filesys -f pathname {} > '{}' 2> '{}'",
-                cmd_name,
-                fs_usage_out_path.display(),
-                fs_usage_err_path.display()
-            ),
-        ])
+        .args(["/usr/bin/fs_usage", "-w", "-f", "filesys", "-f", "pathname", cmd_name])
         .stdin(Stdio::null())
-        .stdout(Stdio::null())
-        .stderr(Stdio::null())
+        .stdout(fs_usage_stdout)
+        .stderr(fs_usage_stderr)
         .spawn()
         .map_err(|e| {
             NonoError::LearnError(format!("Failed to spawn fs_usage (sudo required): {}", e))
@@ -613,7 +612,7 @@ fn run_fs_usage_and_nettop(
     let _ = child.wait();
     debug!("Child process exited");
 
-    // Kill fs_usage. The sudo bash wrapper spawns fs_usage as a child,
+    // Kill fs_usage. The sudo wrapper spawns fs_usage as a child,
     // so we kill both the wrapper and its children.
     kill_fs_usage(&fs_usage);
     let _ = fs_usage.wait();
```