# Directory rename leaves stale parent cache after host failure

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/path_rename.rs:172`

## Summary
A failed directory rename removes the source name from the cached parent inode entries before calling the host `fs_rename`, but the directory error path returns without restoring that cache entry. This leaves the in-memory parent directory state stale and causes later path-based operations to incorrectly report `Noent` for a directory that still exists on the host.

## Provenance
- Verified from the supplied reproducer and source analysis in `lib/wasix/src/syscalls/wasi/path_rename.rs`
- Scanner reference: https://swival.dev

## Preconditions
- Host `fs_rename` fails during a directory rename
- The source parent inode cache remains reused by a later operation
- A subsequent operation resolves the original source name from that stale cached parent

## Proof
In `path_rename_internal`, the implementation removes `source_entry_name` from `source_parent_inode.entries` before attempting the host rename. In the `Kind::Dir` branch at `lib/wasix/src/syscalls/wasi/path_rename.rs:172`, if `state.fs_rename(cloned_path, &host_adjusted_target_path)` returns `Err`, the function returns that error without reinserting the removed source entry.

The reproduced effect is source-grounded:
- the failed rename leaves the cached parent missing the original name;
- `path_remove_directory` consults cached parent entries and returns `Errno::Noent` if the name is absent at `lib/wasix/src/syscalls/wasi/path_remove_directory.rs:51` and `lib/wasix/src/syscalls/wasi/path_remove_directory.rs:62`;
- after rename failure, `path_remove_directory("a")` can therefore fail with `Noent` even though directory `a` still exists on the host.

This reproduces a real post-error state corruption of the parent cache, even if the broader claim about permanent inode-table loss is overstated.

## Why This Is A Real Bug
The syscall reports the host rename failure, but it also mutates cached filesystem state as if the source name were already removed. Because later syscalls trust that cache for directory entry resolution, the failed rename creates an observable mismatch between host state and WASIX in-memory state. That directly causes incorrect user-visible behavior: existing directories can be reported missing until cache repair happens through another lookup path.

## Fix Requirement
On directory rename failure, restore `source_entry` into `source_parent_inode.entries` before returning the host error so the cached parent state remains consistent with the unchanged host filesystem.

## Patch Rationale
The patch reinstates the removed source directory entry on the `Kind::Dir` host-rename error path in `lib/wasix/src/syscalls/wasi/path_rename.rs`. This matches the existing rollback behavior already present for other inode kinds and preserves cache consistency when the rename does not occur.

## Residual Risk
None

## Patch
- Patch file: `052-directory-rename-drops-source-entry-on-host-failure.patch`
- Change: add rollback reinsertion of the removed source directory entry before returning from the directory `fs_rename` failure path in `lib/wasix/src/syscalls/wasi/path_rename.rs`