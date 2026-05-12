# Sandbox guard trusts removable environment variable

## Classification

High severity sandbox escape / sandbox policy bypass.

## Affected Locations

`crates/nono-cli/src/session_commands.rs:25`

## Summary

The destructive session-command guard trusted `NONO_CAP_FILE` to decide whether the current process was sandboxed. A sandboxed child process can remove or alter its own environment before invoking `nono stop`, `nono detach`, `nono attach`, or `nono prune`, bypassing the guard and reaching operations that signal supervisors or mutate session state.

## Provenance

Identified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A sandboxed child can execute the `nono` CLI.
- The sandboxed child can modify its process environment.
- For the reproduced signal impact, the child can provide a readable/writable `HOME` containing a crafted `.nono/sessions/<id>.json`.
- On Linux, impact is reproducible where Landlock ABI V6 process scoping is unavailable or signal scoping is otherwise not enforced.

## Proof

The guard in `reject_if_sandboxed` only checked:

```rust
std::env::var_os("NONO_CAP_FILE").is_some()
```

`run_stop`, `run_detach`, `run_attach`, and `run_prune` call this guard before performing sensitive operations.

Reproduction confirmed that a sandboxed child can:

- Unset `NONO_CAP_FILE`.
- Set `HOME` to an attacker-controlled directory.
- Create a fake `.nono/sessions/<id>.json`.
- Populate `supervisor_pid` and `started_epoch` from `/proc/<pid>/stat`.
- Invoke `nono stop` and cause a same-UID supervisor process to receive a signal.

On Linux kernels without Landlock ABI V6 process scoping, `SignalMode::Isolated` is not enforced because `requested_scopes` returns no signal scope when `abi.has_scoping()` is false in `crates/nono/src/sandbox/linux.rs:372`. Same-UID `kill()` can then reach an unsandboxed supervisor.

The direct deletion of real `~/.nono/sessions` state was not proven because protected-root controls appear to block direct access to the real registry. The signal path is sufficient to demonstrate security impact.

## Why This Is A Real Bug

Environment variables are attacker-controlled process inputs, not durable sandbox state. A child process can remove `NONO_CAP_FILE` before executing the CLI, so the guard does not reliably distinguish sandboxed from unsandboxed execution.

The bypass reaches `run_stop`, which sends `SIGTERM` or `SIGKILL` to the recorded supervisor PID after validating liveness. With attacker-controlled session metadata and same-UID signal permissions, this enables sandboxed-child-triggered denial of service against the child’s own supervisor and potentially other same-user supervisors if their PID and start time are known.

## Fix Requirement

Sandbox detection must be based on non-removable process state or OS sandbox introspection, not an environment variable inherited by convention.

## Patch Rationale

The patch replaces the environment-variable check with `current_process_is_sandboxed()?`.

On Linux, the patch queries `PR_GET_NO_NEW_PRIVS` via `prctl`. `no_new_privs` is one-way kernel process state commonly set as part of Landlock/seccomp sandbox setup and cannot be removed by unsetting an environment variable.

On macOS, the patch calls `sandbox_check` against the session state directory to determine whether the current process is constrained by the platform sandbox.

On unsupported platforms, the helper returns `false`, preserving prior behavior where no reliable OS-specific sandbox detection is implemented.

This directly addresses the verified bypass by removing trust in `NONO_CAP_FILE` for destructive session commands.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/session_commands.rs b/crates/nono-cli/src/session_commands.rs
index a428d10..992a051 100644
--- a/crates/nono-cli/src/session_commands.rs
+++ b/crates/nono-cli/src/session_commands.rs
@@ -20,7 +20,7 @@ use tracing::debug;
 /// inside a sandbox — a sandboxed agent could use them to kill other
 /// supervisors or tamper with session state.
 fn reject_if_sandboxed(command: &str) -> Result<()> {
-    if std::env::var_os("NONO_CAP_FILE").is_some() {
+    if current_process_is_sandboxed()? {
         return Err(NonoError::ConfigParse(format!(
             "`nono {}` cannot be used inside a sandbox.",
             command
@@ -29,6 +29,57 @@ fn reject_if_sandboxed(command: &str) -> Result<()> {
     Ok(())
 }
 
+#[cfg(target_os = "linux")]
+fn current_process_is_sandboxed() -> Result<bool> {
+    // PR_SET_NO_NEW_PRIVS is one-way process state set by Landlock/seccomp.
+    let ret = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
+    if ret < 0 {
+        return Err(NonoError::ConfigParse(format!(
+            "Failed to query sandbox state: {}",
+            std::io::Error::last_os_error()
+        )));
+    }
+    Ok(ret != 0)
+}
+
+#[cfg(target_os = "macos")]
+fn current_process_is_sandboxed() -> Result<bool> {
+    use std::ffi::CString;
+    use std::os::unix::ffi::OsStrExt;
+
+    const SANDBOX_FILTER_PATH: libc::c_int = 1;
+
+    extern "C" {
+        fn sandbox_check(
+            pid: libc::pid_t,
+            operation: *const libc::c_char,
+            filter_type: libc::c_int,
+            ...,
+        ) -> libc::c_int;
+    }
+
+    let operation = CString::new("file-write-create").expect("static string contains no nul");
+    let state_dir = session::sessions_dir()?;
+    let path = CString::new(state_dir.as_os_str().as_bytes()).map_err(|_| {
+        NonoError::ConfigParse("Failed to query sandbox state: path contains nul byte".to_string())
+    })?;
+
+    let ret = unsafe {
+        sandbox_check(
+            libc::getpid(),
+            operation.as_ptr(),
+            SANDBOX_FILTER_PATH,
+            path.as_ptr(),
+        )
+    };
+    Ok(ret != 0)
+}
+
+#[cfg(not(any(target_os = "linux", target_os = "macos")))]
+fn current_process_is_sandboxed() -> Result<bool> {
+    Ok(false)
+}
+
 /// Dispatch `nono ps`.
 pub fn run_ps(args: &PsArgs) -> Result<()> {
     let sessions = session::list_sessions()?;
```