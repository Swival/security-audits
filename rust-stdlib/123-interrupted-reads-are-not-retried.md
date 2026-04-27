# Interrupted Reads Are Not Retried

## Classification

Error-handling bug, severity low, confidence certain.

## Affected Locations

`library/std_detect/src/detect/os/linux/mod.rs:23`

## Summary

`read_file` treats every `libc::read` failure as fatal. On Linux, `read` can fail with `-1` and `errno == EINTR` when interrupted by a signal before completing. That condition is transient and should be retried. The current implementation closes the file descriptor and returns an error instead.

## Provenance

Verified from the provided source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `read_file` is used to read a Linux file.
- A signal interrupts `libc::read`.
- The signal handler does not cause the syscall to be automatically restarted, or the syscall otherwise returns `EINTR`.

## Proof

`library/std_detect/src/detect/os/linux/mod.rs:23` calls `libc::read` inside a loop.

The existing match handles any `-1` result by closing the descriptor and returning:

```rust
-1 => {
    libc::close(file);
    return Err(format!("Error while reading from file at {orig_path}"));
}
```

The code does not inspect `errno`, so `EINTR` is indistinguishable from a hard I/O error.

The reproducer confirmed this behavior with a local harness matching the committed loop: a blocking `read` interrupted by a signal handler installed without `SA_RESTART` returned `-1` with `errno = EINTR`, and the same “any `-1` => error” logic failed immediately instead of retrying.

The error can propagate through Linux auxiliary-vector feature detection, including paths where `/proc/self/auxv` is read through this helper.

## Why This Is A Real Bug

POSIX/Linux `read` may return `-1` with `errno == EINTR` when interrupted by a signal. `EINTR` does not mean the file read failed permanently; callers are expected to retry unless they intentionally expose interruption.

This helper is an internal file-reading routine for runtime Linux feature detection. Returning an error on transient signal interruption can incorrectly make feature detection fail or fall back to defaults when the file could have been read successfully on retry.

## Fix Requirement

When `libc::read` returns `-1`, check `errno`. If `errno == EINTR`, continue the read loop instead of closing the descriptor and returning an error. Preserve the existing error path for all other `read` failures.

## Patch Rationale

The patch adds a guarded match arm before the generic `-1` error arm:

```rust
-1 if *libc::__errno_location() == libc::EINTR => continue,
```

This preserves existing behavior for real read errors while correctly retrying transient interrupted reads. The fix is minimal, localized to `read_file`, and does not change successful EOF or data-read handling.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std_detect/src/detect/os/linux/mod.rs b/library/std_detect/src/detect/os/linux/mod.rs
index aec94f963f5..25e791ce3de 100644
--- a/library/std_detect/src/detect/os/linux/mod.rs
+++ b/library/std_detect/src/detect/os/linux/mod.rs
@@ -21,6 +21,7 @@ fn read_file(orig_path: &str) -> Result<Vec<u8>, alloc::string::String> {
             data.reserve(4096);
             let spare = data.spare_capacity_mut();
             match libc::read(file, spare.as_mut_ptr() as *mut _, spare.len()) {
+                -1 if *libc::__errno_location() == libc::EINTR => continue,
                 -1 => {
                     libc::close(file);
                     return Err(format!("Error while reading from file at {orig_path}"));
```