# Parent entry removed before unlink succeeds

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/path_unlink_file.rs:57`

## Summary
`path_unlink_file_internal` mutates virtual filesystem metadata before attempting the host unlink. It removes the child from the parent directory map and decrements `st_nlink`, then calls `h.unlink()` or `state.fs_remove_file()`. If the host unlink fails, the function returns early and leaves the inode cache mutated despite the host file still existing.

## Provenance
- Verified from the supplied finding and reproducer
- Reproduced against the current code path in `lib/wasix/src/syscalls/wasi/path_unlink_file.rs`
- Scanner source: https://swival.dev

## Preconditions
- Target file is at its last link
- The host unlink operation can fail after the guest reaches `path_unlink_file_internal`
- At least one open file descriptor can retain the inode after the failed unlink

## Proof
Before the patch, the unlink path removed `childs_name` from the parent `entries` map and decremented the inode link count before invoking the host-side deletion. On host unlink failure, `wasi_try_ok!` returned immediately without restoring either mutation.

This was reproduced in a practical state:
- an open FD kept the old inode alive
- the host unlink failed in `lib/virtual-fs/src/host_fs.rs:535`
- `fd_filestat_get` read the cached inode stat through `lib/wasix/src/fs/mod.rs:1559` and `lib/wasix/src/syscalls/wasi/fd_filestat_get.rs:58`
- the guest observed a still-existing file through the live FD with `st_nlink == 0` even though the host file remained present

## Why This Is A Real Bug
This creates guest-visible split-brain state. Existing descriptors observe the preexisting inode with mutated metadata, while the backing host file was never deleted. A later path lookup can materialize a fresh inode for the same host file with normal metadata, so the same file is simultaneously represented by inconsistent guest objects. That is a concrete integrity violation, not a theoretical inconsistency.

## Fix Requirement
Attempt the host unlink first. Only remove the directory entry and decrement `st_nlink` after the host unlink succeeds.

## Patch Rationale
The patch reorders the operation sequence in `lib/wasix/src/syscalls/wasi/path_unlink_file.rs` so external deletion is the commit point. If unlink fails, the function now exits with virtual metadata untouched. If unlink succeeds, the parent entry removal and link-count decrement proceed, preserving consistency between host state and cached inode state.

## Residual Risk
None

## Patch
- Patch file: `060-parent-entry-removed-before-unlink-succeeds.patch`
- Change: move the host unlink call ahead of parent entry removal and `st_nlink` mutation in `lib/wasix/src/syscalls/wasi/path_unlink_file.rs`
- Result: failed unlink no longer corrupts the virtual inode cache or parent directory state