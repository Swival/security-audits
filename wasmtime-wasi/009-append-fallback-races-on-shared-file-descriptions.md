# Append fallback races on shared file descriptions

## Classification
- Type: race condition
- Severity: medium
- Confidence: certain

## Affected Locations
- `crates/wasi/src/filesystem/unix.rs:61`

## Summary
`append_cursor_unspecified` falls back from `pwritev2(..., APPEND)` to temporarily enabling `O_APPEND` with `F_SETFL`, issuing `write`, then restoring the prior flags. `F_SETFL` mutates the shared file description, so the fallback changes append behavior for all aliases of that description during the window. A concurrent positioned write using the same shared description can therefore be appended instead of written at its requested offset.

## Provenance
- Verified from repository code and reproduced from the documented fallback behavior in `crates/wasi/src/filesystem/unix.rs:61`
- Reproducer confirms the issue on targets where `pwritev2(..., APPEND)` is unavailable or unsupported
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- Shared file description is used concurrently
- Runtime is non-Linux, or Linux where `pwritev2(..., APPEND)` returns `NOSYS` or `NOTSUP`

## Proof
The affected helper falls back as follows:
```rust
let old_flags = fcntl_getfl(fd)?;
fcntl_setfl(fd, old_flags | rustix::fs::OFlags::APPEND)?;
let result = write(fd, buf);
fcntl_setfl(fd, old_flags)?;
```

This sequence is unsafe because `F_SETFL` applies to the underlying file description, not only to the calling operation. While `O_APPEND` is temporarily set, any concurrent write path using the same description can observe append mode. On platforms documenting append interaction at the kernel level, this causes positioned writes to append without changing the file offset rather than writing at the caller-specified offset.

The reproduced trigger is:
- use a target that reaches the fallback path
- share one file description across concurrent append and positioned-write operations
- execute the positioned write during the temporary `O_APPEND` window

Observed result: the positioned write can land at end-of-file instead of at its intended offset.

## Why This Is A Real Bug
This is a direct data-integrity failure, not a theoretical synchronization concern. The helper is intended to provide append semantics for one call, but instead modifies global state on the shared description. That violates isolation between concurrent file operations and can redirect writes to the wrong location. The issue is source-provable from the fallback implementation and consistent with documented kernel behavior on affected platforms.

## Fix Requirement
Do not toggle shared `O_APPEND` on the original file description. The fallback must use an append-capable syscall that is per-operation, or perform the append through a separately opened append-only descriptor that does not mutate shared state.

## Patch Rationale
The patch removes the shared-state `F_SETFL` fallback and replaces it with a safe mechanism that preserves per-call append semantics without changing flags on the original file description. This eliminates the race window and prevents concurrent positioned writes from being silently redirected to end-of-file.

## Residual Risk
None

## Patch
- Patch file: `009-append-fallback-races-on-shared-file-descriptions.patch`