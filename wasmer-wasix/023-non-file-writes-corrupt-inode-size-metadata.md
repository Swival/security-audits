# Non-file writes corrupt inode size metadata

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/fd_write.rs:425`

## Summary
Successful writes to non-file descriptors incorrectly mutated shared inode `st_size`. In `fd_write_internal`, socket and pipe paths returned `is_file = false`, but the common post-write block still incremented `fd_entry.inode.stat.st_size` for every non-stdio write. As a result, `fd_write` and `fd_pwrite` against sockets or pipes corrupted metadata that later surfaced through `fd_filestat_get`.

## Provenance
- Verified finding reproduced and patched from Swival Security Scanner: https://swival.dev
- Reproduced from the reported path `lib/wasix/src/syscalls/wasi/fd_write.rs:425`

## Preconditions
- Write access to a socket or pipe descriptor

## Proof
- Guest buffers from `iovs` flow into `fd_write_internal`.
- `Kind::Socket`, `Kind::PipeTx`, and `Kind::DuplexPipe` return successful write results with `is_file = false`.
- The shared post-write path then checks `!is_stdio` and increments `fd_entry.inode.stat.write().unwrap().st_size += bytes_written as u64`.
- Because this branch was not restricted to real files, socket and pipe writes accumulated `st_size` despite lacking file-length semantics.
- Reproduction confirmed that writing N bytes to a socket or pipe, then calling `fd_filestat_get` on the same fd, increased `st_size` by N.
- The corruption persists across duplicated descriptors because duped fds share inode state in `lib/wasix/src/fs/mod.rs:1885`, `lib/wasix/src/fs/mod.rs:1892`, and `lib/wasix/src/fs/mod.rs:1903`.

## Why This Is A Real Bug
`st_size` is meaningful for regular files, not sockets or pipes. Updating it for non-file descriptors creates false filesystem metadata, breaks filestat consumers, and contaminates shared inode state across duplicated descriptors. The issue is reachable through normal syscall entrypoints and was reproduced end-to-end.

## Fix Requirement
Only mutate `st_size` for real file writes. Do not change inode size metadata for sockets, pipes, or any other non-file descriptor kinds.

## Patch Rationale
The patch gates the post-write size update on `is_file` instead of `!is_stdio`. This preserves existing file behavior while preventing metadata mutation for sockets, pipes, and other non-file write targets that pass through the same shared completion path.

## Residual Risk
None

## Patch
- Patched in `023-non-file-writes-corrupt-inode-size-metadata.patch`
- Updated `lib/wasix/src/syscalls/wasi/fd_write.rs` so the shared post-write block only increments `st_size` when `is_file` is true
- This preserves file length accounting and eliminates inode size corruption for sockets and pipes