# restore failure leaks saved descriptor

## Classification

Resource lifecycle bug, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/process/unix/vxworks.rs:100`

## Summary

VxWorks `Command::spawn` saves redirected standard descriptors with raw `libc::dup`, restores them after `rtpSpawn` with `dup2`, and then manually closes the saved descriptors. If a restore `dup2` fails, the `t!` macro returns immediately before the corresponding `close`, leaking the saved descriptor.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `Command::spawn` runs on VxWorks.
- `stdin` was redirected so `theirs.stdin.fd()` returns `Some`.
- `libc::dup(STDIN_FILENO)` succeeds and stores a saved descriptor in `orig_stdin`.
- Restore via `libc::dup2(orig_stdin, STDIN_FILENO)` fails.

## Proof

Redirected stdin reaches the vulnerable path when `theirs.stdin.fd()` is `Some`. The source saves the original stdin with:

```rust
orig_stdin = t!(cvt_r(|| libc::dup(libc::STDIN_FILENO)));
```

After `rtpSpawn`, restoration uses:

```rust
t!(cvt_r(|| libc::dup2(orig_stdin, libc::STDIN_FILENO)));
libc::close(orig_stdin);
```

The local `t!` macro expands errors to an immediate return:

```rust
Err(e) => return Err(e.into()),
```

Therefore, when `dup2(orig_stdin, STDIN_FILENO)` fails, control returns before `libc::close(orig_stdin)` executes. Because `orig_stdin` is a plain `c_int` rather than an RAII-managed `FileDesc`, no later cleanup closes it.

## Why This Is A Real Bug

The saved descriptor is allocated by `dup` and must be closed manually. The code explicitly acknowledges this requirement:

```rust
// Because FileDesc was not used, each duplicated file descriptor
// needs to be closed manually
```

The failing restore path violates that lifecycle rule. Each failed restore after redirected stdin can leak one descriptor. The same pattern also exists for stdout and stderr restore paths, where `t!` can return before `close`.

## Fix Requirement

Close saved descriptors on every restore error path before returning the error. Cleanup must include the descriptor whose restore failed and any later saved descriptors that would otherwise be skipped by the early return.

## Patch Rationale

The patch replaces `t!(cvt_r(|| libc::dup2(...)))` on restore paths with explicit `if let Err(e)` handling.

On stdin restore failure, it closes:

- `orig_stdin`, the descriptor whose restore failed.
- `orig_stdout`, if it was saved and would otherwise be skipped.
- `orig_stderr`, if it was saved and would otherwise be skipped.

On stdout restore failure, it closes:

- `orig_stdout`, the descriptor whose restore failed.
- `orig_stderr`, if it was saved and would otherwise be skipped.

On stderr restore failure, it closes:

- `orig_stderr`, the descriptor whose restore failed.

This preserves the original error return behavior while ensuring saved descriptors are not leaked on restore failure paths.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/process/unix/vxworks.rs b/library/std/src/sys/process/unix/vxworks.rs
index 346ca6d74c9..6247a2ed225 100644
--- a/library/std/src/sys/process/unix/vxworks.rs
+++ b/library/std/src/sys/process/unix/vxworks.rs
@@ -97,15 +97,33 @@ macro_rules! t {
             // Because FileDesc was not used, each duplicated file descriptor
             // needs to be closed manually
             if orig_stdin != libc::STDIN_FILENO {
-                t!(cvt_r(|| libc::dup2(orig_stdin, libc::STDIN_FILENO)));
+                if let Err(e) = cvt_r(|| libc::dup2(orig_stdin, libc::STDIN_FILENO)) {
+                    libc::close(orig_stdin);
+                    if orig_stdout != libc::STDOUT_FILENO {
+                        libc::close(orig_stdout);
+                    }
+                    if orig_stderr != libc::STDERR_FILENO {
+                        libc::close(orig_stderr);
+                    }
+                    return Err(e.into());
+                }
                 libc::close(orig_stdin);
             }
             if orig_stdout != libc::STDOUT_FILENO {
-                t!(cvt_r(|| libc::dup2(orig_stdout, libc::STDOUT_FILENO)));
+                if let Err(e) = cvt_r(|| libc::dup2(orig_stdout, libc::STDOUT_FILENO)) {
+                    libc::close(orig_stdout);
+                    if orig_stderr != libc::STDERR_FILENO {
+                        libc::close(orig_stderr);
+                    }
+                    return Err(e.into());
+                }
                 libc::close(orig_stdout);
             }
             if orig_stderr != libc::STDERR_FILENO {
-                t!(cvt_r(|| libc::dup2(orig_stderr, libc::STDERR_FILENO)));
+                if let Err(e) = cvt_r(|| libc::dup2(orig_stderr, libc::STDERR_FILENO)) {
+                    libc::close(orig_stderr);
+                    return Err(e.into());
+                }
                 libc::close(orig_stderr);
             }
```