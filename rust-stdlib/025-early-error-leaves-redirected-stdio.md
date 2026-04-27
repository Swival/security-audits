# Early Error Leaves Redirected Stdio

## Classification

Resource lifecycle bug, high severity.

## Affected Locations

- `library/std/src/sys/process/unix/vxworks.rs:59`

## Summary

The VxWorks `Command::spawn` implementation temporarily redirects process-global stdio with `dup2` before calling `rtpSpawn`, but early error paths return before restoring descriptors. If stdin is redirected successfully and a later setup step fails, the parent process keeps the redirected fd installed as fd 0. Similar corruption can occur for stdout or stderr after partial setup.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `Command::spawn` is used on the VxWorks backend.
- At least one stdio stream is redirected successfully.
- A later operation fails before the post-`rtpSpawn` restoration block runs.
- Example: stdin redirection succeeds, then `current_dir` points to a missing directory and `chdir` fails.

## Proof

The implementation duplicates and replaces standard descriptors before spawning:

```rust
if let Some(fd) = theirs.stdin.fd() {
    orig_stdin = t!(cvt_r(|| libc::dup(libc::STDIN_FILENO)));
    t!(cvt_r(|| libc::dup2(fd, libc::STDIN_FILENO)));
}
```

Later setup uses the same `t!` macro:

```rust
if let Some(cwd) = self.get_cwd() {
    t!(cvt(libc::chdir(cwd.as_ptr())));
}
```

Before the patch, `t!` returned immediately on error:

```rust
Err(e) => return Err(e.into()),
```

The descriptor restoration block appeared only after `rtpSpawn`, so an error from stdout `dup2`, stderr `dup2`, `chdir`, or another later `t!` skipped cleanup.

A safe reproducer is:

```rust
use std::{fs::File, process::Command};

let input = File::open("some_existing_file").unwrap();

let err = Command::new("some_program")
    .stdin(input)
    .current_dir("definitely-does-not-exist")
    .spawn();

assert!(err.is_err());
```

On the affected implementation, `spawn()` returns `Err`, but fd 0 in the parent process remains redirected to `some_existing_file`.

## Why This Is A Real Bug

`dup2(fd, STDIN_FILENO)` replaces the process-global stdin descriptor. Dropping the command-side `File` or returning `Err` does not undo that replacement. A failed `Command::spawn` is expected not to permanently mutate the caller’s stdio, but this path leaves the parent process corrupted after an ordinary safe Rust API call.

## Fix Requirement

Restore and close any saved original descriptors before every early return after stdio redirection begins.

## Patch Rationale

The patch moves the saved descriptor variables before the `t!` macro and changes `t!` so every error path attempts best-effort restoration of stdin, stdout, and stderr before returning. It also resets descriptor sentinels after normal restoration, preventing the error-aware macro from trying to restore or close already-restored descriptors if a later restoration step fails.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/unix/vxworks.rs b/library/std/src/sys/process/unix/vxworks.rs
index 346ca6d74c9..bc1dc68d91a 100644
--- a/library/std/src/sys/process/unix/vxworks.rs
+++ b/library/std/src/sys/process/unix/vxworks.rs
@@ -37,19 +37,33 @@ pub fn spawn(
         let mut p = Process { pid: 0, status: None };
 
         unsafe {
+            let mut orig_stdin = libc::STDIN_FILENO;
+            let mut orig_stdout = libc::STDOUT_FILENO;
+            let mut orig_stderr = libc::STDERR_FILENO;
+
             macro_rules! t {
                 ($e:expr) => {
                     match $e {
                         Ok(e) => e,
-                        Err(e) => return Err(e.into()),
+                        Err(e) => {
+                            if orig_stdin != libc::STDIN_FILENO {
+                                let _ = cvt_r(|| libc::dup2(orig_stdin, libc::STDIN_FILENO));
+                                libc::close(orig_stdin);
+                            }
+                            if orig_stdout != libc::STDOUT_FILENO {
+                                let _ = cvt_r(|| libc::dup2(orig_stdout, libc::STDOUT_FILENO));
+                                libc::close(orig_stdout);
+                            }
+                            if orig_stderr != libc::STDERR_FILENO {
+                                let _ = cvt_r(|| libc::dup2(orig_stderr, libc::STDERR_FILENO));
+                                libc::close(orig_stderr);
+                            }
+                            return Err(e.into());
+                        }
                     }
                 };
             }
 
-            let mut orig_stdin = libc::STDIN_FILENO;
-            let mut orig_stdout = libc::STDOUT_FILENO;
-            let mut orig_stderr = libc::STDERR_FILENO;
-
             if let Some(fd) = theirs.stdin.fd() {
                 orig_stdin = t!(cvt_r(|| libc::dup(libc::STDIN_FILENO)));
                 t!(cvt_r(|| libc::dup2(fd, libc::STDIN_FILENO)));
@@ -99,10 +113,12 @@ macro_rules! t {
             if orig_stdin != libc::STDIN_FILENO {
                 t!(cvt_r(|| libc::dup2(orig_stdin, libc::STDIN_FILENO)));
                 libc::close(orig_stdin);
+                orig_stdin = libc::STDIN_FILENO;
             }
             if orig_stdout != libc::STDOUT_FILENO {
                 t!(cvt_r(|| libc::dup2(orig_stdout, libc::STDOUT_FILENO)));
                 libc::close(orig_stdout);
+                orig_stdout = libc::STDOUT_FILENO;
             }
             if orig_stderr != libc::STDERR_FILENO {
                 t!(cvt_r(|| libc::dup2(orig_stderr, libc::STDERR_FILENO)));
```