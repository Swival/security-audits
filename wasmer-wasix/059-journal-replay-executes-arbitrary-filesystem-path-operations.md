# Journal replay replays forged root-scoped path operations

## Classification
- Type: trust-boundary violation
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/journal/play_event.rs:110`
- `lib/wasix/src/journal/effector/syscalls/chdir.rs:8`
- `lib/wasix/src/syscalls/wasix/chdir.rs:33`

## Summary
`play_event` trusts path-bearing `JournalEntry` values during replay and forwards them to `JournalEffector` path mutators without confining them to the authority implied by the recorded directory FDs. A forged replay entry can substitute `VIRTUAL_ROOT_FD` plus attacker-chosen paths and successfully create, delete, rename, link, or switch cwd anywhere within the mounted WASIX root, including host-backed mounts exposed there.

## Provenance
- Verified from the supplied reproducer and source inspection in `lib/wasix/src/syscalls/journal/play_event.rs:110`
- Reproduced against replay handling for `RemoveDirectoryV1`, `UnlinkFileV1`, `PathRenameV1`, `CreateDirectoryV1`, `CreateHardLinkV1`, `CreateSymbolicLinkV1`, and `ChangeDirectoryV1`
- Scanner reference: https://swival.dev

## Preconditions
- Ability to supply or tamper with a replayed journal entry

## Proof
- `play_event` reads `path`, `old_path`, and `new_path` directly from `JournalEntry` variants and calls `JournalEffector::apply_path_remove_directory`, `apply_path_unlink`, `apply_path_rename`, `apply_path_create_directory`, `apply_path_link`, `apply_path_symlink`, and `apply_chdir` with no local validation in `lib/wasix/src/syscalls/journal/play_event.rs:110`
- Replay accepts forged entries such as `RemoveDirectoryV1 { fd: 3, path: "/host/x" }`, `UnlinkFileV1 { fd: 3, path: "/host/x" }`, and `PathRenameV1 { old_fd: 3, old_path: "/host/a", new_fd: 3, new_path: "/host/b" }`
- These entries succeed when `fd` is the replay-visible virtual root descriptor, allowing mutation anywhere inside the mounted WASIX root rather than only within the original guest-authorized directory subtree
- `ChangeDirectoryV1` is also reachable: `lib/wasix/src/journal/effector/syscalls/chdir.rs:8` delegates to `lib/wasix/src/syscalls/wasix/chdir.rs:33`, which checks path existence and then updates `current_dir`, so forged replay can relocate cwd anywhere under the mounted root

## Why This Is A Real Bug
Replay is crossing a trust boundary: journal contents are treated as authoritative capability-bearing path operations even though the original access control depended on the directory FD context at record time. By forging replay entries to use the root descriptor and arbitrary in-root paths, an attacker expands authority and causes real filesystem side effects on mounted content, including host-backed mounts. This is an authorization failure, not a harmless integrity mismatch.

## Fix Requirement
Reject replayed path operations that use absolute or escaping paths and ensure replayed paths remain confined to the directory capability intended by the recorded FD before calling `JournalEffector`.

## Patch Rationale
The patch in `059-journal-replay-executes-arbitrary-filesystem-path-operations.patch` adds replay-side path validation and confinement in `lib/wasix/src/syscalls/journal/play_event.rs` so path-bearing journal entries are normalized and rejected before dispatch if they are absolute, escape via traversal, or otherwise exceed the allowed replay scope. This restores the original capability boundary during journal replay instead of trusting raw serialized paths.

## Residual Risk
None

## Patch
- Patch file: `059-journal-replay-executes-arbitrary-filesystem-path-operations.patch`
- Effect: hardens journal replay by validating and confining replayed paths before invoking `JournalEffector` path and cwd operations
- Result: forged journal entries can no longer use root-scoped or escaping paths to mutate arbitrary locations within the mounted WASIX root