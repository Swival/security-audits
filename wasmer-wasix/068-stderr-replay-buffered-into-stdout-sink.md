# Stderr replay buffered into stdout sink

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/journal/actions/fd_write.rs:20`

## Summary
During journal replay, stderr-buffered writes are appended to the stdout replay sink. When replay later flushes buffered stdio, bytes originally written to stderr are emitted on stdout, while stderr remains empty for those writes.

## Provenance
- Verified from the supplied reproducer and code-path analysis
- Reference: https://swival.dev

## Preconditions
- Stderr replay buffering is enabled
- The replayed file descriptor is included in `stderr_fds`
- The buffered write reaches a later snapshot-driven flush path

## Proof
`action_fd_write` accepts replay input `fd`, `offset`, `data`, and `is_64bit`. In the stderr branch, when `self.stderr_fds.contains(&fd)` is true, the implementation appends `JournalStdIoWrite` into `self.stdout.as_mut()` rather than `self.stderr`, misrouting stderr bytes at `lib/wasix/src/syscalls/journal/actions/fd_write.rs:20`.

The reproduced path shows snapshot replay invoking this write handler for fd 2 from `lib/wasix/src/syscalls/journal/actions/snapshot.rs:30` and `lib/wasix/src/syscalls/journal/actions/snapshot.rs:33`. Flush-time behavior is externally visible in `lib/wasix/src/syscalls/journal/restore_snapshot.rs:37`, `lib/wasix/src/syscalls/journal/restore_snapshot.rs:46`, `lib/wasix/src/syscalls/journal/restore_snapshot.rs:54`, and `lib/wasix/src/syscalls/journal/restore_snapshot.rs:63`: `runner.stdout` is written to fd 1, while `runner.stderr` is written to fd 2. Because replayed stderr bytes were stored in `runner.stdout`, they are emitted on stdout instead of stderr.

## Why This Is A Real Bug
This violates stdout/stderr stream separation and corrupts replayed process output. The effect is observable outside the process at restore time, where consumers receive stderr content on stdout. That is a concrete integrity failure, not a cosmetic issue.

## Fix Requirement
Change the stderr buffering branch in `lib/wasix/src/syscalls/journal/actions/fd_write.rs` so replayed stderr writes are pushed into `self.stderr.as_mut()` instead of `self.stdout.as_mut()`.

## Patch Rationale
The bug is a direct sink-selection error in the stderr branch. Redirecting buffered entries to `self.stderr` restores the intended one-to-one mapping between replayed stderr writes and the stderr flush path, without altering unrelated replay behavior.

## Residual Risk
None

## Patch
- Patch file: `068-stderr-replay-buffered-into-stdout-sink.patch`
- Change: replace the stderr-branch append target from `self.stdout.as_mut()` to `self.stderr.as_mut()` in `lib/wasix/src/syscalls/journal/actions/fd_write.rs:20`