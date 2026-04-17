# EventNotifications partial writes misreport bytes written

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/fd_write.rs:349`
- `lib/wasix/src/syscalls/wasi/fd_write.rs:441`
- `lib/wasix/src/syscalls/wasi/fd_write.rs:503`
- `lib/wasix/src/syscalls/wasi/fd_write.rs:519`
- `lib/wasix/src/syscalls/wasi/fd_write.rs:551`
- `lib/wasix/src/syscalls/wasi/fd_filestat_get.rs:47`
- `lib/wasix/src/fs/mod.rs:1559`

## Summary
`fd_write`/`fd_pwrite` on `EventNotifications` file descriptors accepted buffers whose lengths were not multiples of `u64`, processed only full 8-byte chunks, but still reported the entire guest-supplied byte length as written. This inflated `nwritten`, advanced cached file size accounting, and caused journal capture to persist a byte count that did not match the effective eventfd state change.

## Provenance
- Verified from the provided reproducer and source analysis
- Scanner source: https://swival.dev

## Preconditions
- Writable `EventNotifications` file descriptor
- Guest supplies an iovec whose `buf_len` is not divisible by 8

## Proof
In `Kind::EventNotifications`, the write path derived `val_cnt = buf_len / size_of::<u64>()`, so only complete `u64` values were read and submitted to `inner.write(*val)`. However, the same path set `will_be_written = buf_len` and added that amount into `written`.

This mismatch is reachable from live `fd_write`/`fd_pwrite` handling and was reproduced. The downstream effects are observable in two places:
- filestat growth used `bytes_written`, so `_size += bytes_written` inflated the event fd size despite only full `u64` chunks affecting the notification counter at `lib/wasix/src/syscalls/wasi/fd_write.rs:519` and `lib/wasix/src/syscalls/wasi/fd_write.rs:551`
- journal capture also trusted `bytes_written` and snapshotted that many raw bytes from guest iovecs at `lib/wasix/src/syscalls/wasi/fd_write.rs:503` and `lib/wasix/src/journal/effector/syscalls/fd_write.rs:17`

A second source-level inconsistency existed in the journal replay `Buffer` branch for `EventNotifications`: it ignored trailing bytes and never incremented its local `written` counter at `lib/wasix/src/syscalls/wasi/fd_write.rs:441`.

## Why This Is A Real Bug
This is not a cosmetic accounting issue. WASI callers consume `nwritten` to determine how many bytes were accepted, and the runtime uses the same count to update cached metadata and journal state. When trailing bytes are dropped but still reported as written, the API violates write semantics and persists incorrect state into filestat and journal artifacts. That is a concrete integrity failure on a reachable syscall path.

## Fix Requirement
Only report bytes corresponding to complete `u64` notifications for `EventNotifications`, or reject non-8-byte-aligned buffers with `Errno::Inval`. The accounting used for `nwritten`, cached stat updates, and journaling must all derive from the actual number of processed bytes.

## Patch Rationale
The patch in `022-eventnotifications-overreports-bytes-for-partial-u64-input.patch` normalizes `EventNotifications` accounting to the number of complete `u64` values actually consumed. This removes false positive byte counts on the live write path and keeps journal-related handling aligned with effective writes, preventing filestat and snapshot inflation from partial trailing input.

## Residual Risk
None

## Patch
- `022-eventnotifications-overreports-bytes-for-partial-u64-input.patch`