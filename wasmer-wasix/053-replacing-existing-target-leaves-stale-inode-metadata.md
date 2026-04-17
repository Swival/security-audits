# Rename replacement now swaps cached inode entry

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasi/path_rename.rs:238`
- `lib/wasix/src/syscalls/wasi/path_rename.rs:281`
- `lib/wasix/src/syscalls/wasix/path_open2.rs:256`
- `lib/wasix/src/fs/mod.rs:2223`

## Summary
Replacing an existing destination during `path_rename` left the old destination inode cached in the target directory entry table. After the on-disk rename succeeded, later lookups of the destination path could still resolve to the stale cached inode, including a previously opened `handle`, so ordinary re-open operations could return the unlinked old file instead of the moved source file.

## Provenance
- Verified from the provided source-grounded reproducer and patch requirements
- Scanner: https://swival.dev

## Preconditions
- Target path already exists before rename
- The destination inode was previously cached, including a live `handle: Some(...)`

## Proof
- `path_rename` resolves the destination path and sets `need_create = false` when the target already exists.
- The syscall removes the source entry and performs the filesystem rename.
- In the replacement path, code does not overwrite `target_parent_inode.entries` with `source_entry`.
- Instead, it re-fetches the existing destination inode and updates only superficial fields such as `name` and `st_size`.
- `path_open2` reuses cached inodes/handles for ordinary opens, so a later open of the destination path can return the stale cached handle for the old destination object.
- The reproducer confirms this sequence is reachable and returns the wrong file after a successful replace.

## Why This Is A Real Bug
The directory cache and inode table no longer match the filesystem after a successful rename-over-existing-target. That violates the core invariant that a directory entry for a path must resolve to the inode now present at that path. Because reopen logic consumes cached handles, this is not a metadata-only discrepancy; it can return access to the wrong file object after the rename has completed successfully.

## Fix Requirement
On rename-over-existing-target, replace the target directory entry with `source_entry` and refresh the moved inode metadata, including any path-sensitive state for descendants when needed. The stale destination inode must not remain reachable through the target path cache.

## Patch Rationale
The patch in `053-replacing-existing-target-leaves-stale-inode-metadata.patch` fixes the bug by swapping the moved source inode into the target directory cache instead of mutating the old destination inode in place. This preserves cache-to-filesystem consistency and ensures subsequent `path_open2` lookups resolve the renamed source rather than any stale cached destination handle.

## Residual Risk
None

## Patch
- Patched file: `053-replacing-existing-target-leaves-stale-inode-metadata.patch`
- Effect: rename-over-existing-target now updates the target entry to the moved inode and refreshes inode metadata so cached lookups align with the post-rename filesystem state.