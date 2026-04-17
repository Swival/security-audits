# Opened fd ignores requested base rights

## Classification
- Type: authorization flaw
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/path_open2.rs:113`
- `lib/wasix/src/syscalls/wasix/path_open2.rs:163`
- `lib/wasix/src/fs/mod.rs:1606`

## Summary
`path_open2` accepts caller-supplied `fs_rights_base` but `path_open_internal` derives the returned fd base rights from the parent directory's inheriting rights instead. This causes the newly opened fd to retain broader capabilities than the caller requested. When the parent inheriting rights include `FD_WRITE`, the code also opens the host file writable, so the guest can successfully write through the returned fd despite omitting write rights in the request.

## Provenance
- Verified from the supplied reproducer and source inspection in `lib/wasix/src/syscalls/wasix/path_open2.rs`
- Swival Security Scanner: https://swival.dev

## Preconditions
- The directory fd used for `path_open2` has broader `rights_inheriting` than the caller's requested `fs_rights_base`

## Proof
- `path_open2` forwards caller-controlled `fs_rights_base` into `path_open_internal` at `lib/wasix/src/syscalls/wasix/path_open2.rs:113`
- Inside `path_open_internal`, `adjusted_rights` is assigned from `working_dir_rights_inheriting` while `fs_rights_base` is commented out, so requested base rights are ignored before fd creation
- The open-mode decision checks `adjusted_rights.contains(Rights::FD_WRITE)` at `lib/wasix/src/syscalls/wasix/path_open2.rs:163`, making the host handle writable whenever the parent inheriting rights include write
- `create_fd` / `with_fd` stores `adjusted_rights` as the new fd base rights, so the capability expansion persists on the returned descriptor
- `fd_fdstat_get` reports `fd.inner.rights` back to the guest at `lib/wasix/src/fs/mod.rs:1606`, confirming the broadened rights are observable and durable
- Reproducer path:
```text
1. Use a preopened directory fd whose inheriting rights include FD_WRITE.
2. Call path_open2/path_open on an existing file with fs_rights_base excluding FD_WRITE.
3. path_open_internal assigns parent inheriting rights to the new fd base rights.
4. Call fd_write on the returned fd; authorization succeeds and the file can be modified.
```

## Why This Is A Real Bug
The syscall contract exposes `fs_rights_base` as the caller's requested base capability set for the returned fd. Ignoring that value violates least privilege and upgrades authority relative to the request. This is not cosmetic metadata drift: the same broadened rights control both host open flags and subsequent guest authorization, enabling writes that the caller explicitly declined to request.

## Fix Requirement
Compute returned fd base rights as the intersection of requested base rights and the parent directory's inheriting rights before any open-mode or fd creation logic. In practice, set base rights to `fs_rights_base & working_dir_rights_inheriting`.

## Patch Rationale
The patch constrains `adjusted_rights` to `fs_rights_base & working_dir_rights_inheriting` in `lib/wasix/src/syscalls/wasix/path_open2.rs`, so:
- the host file is only opened with write access when the caller requested write and the parent may confer it
- the stored fd base rights match the requested capability subset
- subsequent rights checks and `fd_fdstat_get` reflect the intended least-privilege descriptor

## Residual Risk
None

## Patch
- Patch file: `039-opened-fd-ignores-requested-base-rights.patch`
- Required change in `lib/wasix/src/syscalls/wasix/path_open2.rs`: replace the current `adjusted_rights` assignment with `fs_rights_base & working_dir_rights_inheriting`
- This single change aligns fd creation, open-mode selection, and reported rights with the caller-requested base rights ceiling