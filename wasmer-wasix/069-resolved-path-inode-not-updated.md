# Resolved path inode not updated

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/path_filestat_set_times.rs:71`

## Summary
`path_filestat_set_times_internal` resolves the guest-supplied `path` to `file_inode`, but applies `st_atim` and `st_mtim` updates to `fd_inode`, which is the base directory inode obtained from the directory file descriptor. When `path` refers to a different entry, the syscall mutates the wrong inode and leaves the intended target unchanged.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner reference: https://swival.dev

## Preconditions
- Valid directory fd with `PATH_FILESTAT_SET_TIMES` right and a resolvable path

## Proof
- In `lib/wasix/src/syscalls/wasi/path_filestat_set_times.rs:71`, the syscall resolves `file_inode = state.fs.get_inode_at_path(...)`.
- The timestamp writes then target `fd_inode.stat.write().unwrap()`, where `fd_inode` was derived from `state.fs.get_fd(fd)?.inode`, i.e. the base directory fd.
- Therefore, for any successful call where `path` names a child entry instead of the directory itself, the base directory inode receives the new timestamps while the resolved child inode does not.
- This is externally observable: `fd_filestat_get(fd)` reads the base fd inode stat in `lib/wasix/src/fs/mod.rs:1559`, while `path_filestat_get` reads from the resolved inode in `lib/wasix/src/syscalls/wasi/path_filestat_get.rs:75` and `lib/wasix/src/syscalls/wasi/path_filestat_get.rs:83`.

## Why This Is A Real Bug
The syscall contract is path-based, and the implementation already performs path resolution to identify the target object. Ignoring that resolved inode causes successful calls to corrupt metadata on a different filesystem object. This is a direct integrity violation, not a theoretical mismatch, because the wrong-object mutation is observable through existing filestat APIs.

## Fix Requirement
Update `path_filestat_set_times_internal` so that timestamp writes are applied to the resolved `file_inode` stat, not the base directory `fd_inode` stat.

## Patch Rationale
The patch changes the write target from the directory fd inode to the inode returned by path resolution. This aligns the mutation with the syscall's path-based semantics and with companion path-based metadata reads.

## Residual Risk
None

## Patch
- Patch file: `069-resolved-path-inode-not-updated.patch`
- The patch updates `lib/wasix/src/syscalls/wasi/path_filestat_set_times.rs` to write `st_atim` and `st_mtim` through the resolved `file_inode` state instead of `fd_inode`.