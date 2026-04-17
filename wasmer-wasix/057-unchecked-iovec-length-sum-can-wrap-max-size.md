# Unchecked iovec length sum can wrap max_size

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/syscalls/wasix/sock_recv_from.rs:49`

## Summary
`sock_recv_from_internal` accumulates guest-provided iovec lengths into `max_size` using unchecked `usize` addition. On `Memory64`, a malformed set of `buf_len` values can wrap `max_size` in release builds, causing the syscall to size the temporary receive buffer from a truncated sum instead of rejecting the request with `Errno::Overflow`.

## Provenance
- Verified from the supplied reproducer and source review
- Scanner provenance: https://swival.dev

## Preconditions
- Attacker controls `ri_data` iovec descriptors
- The supplied iovec lengths sum past `usize::MAX`

## Proof
At `lib/wasix/src/syscalls/wasix/sock_recv_from.rs:49`, the syscall iterates over `ri_data` and adds each `iovs.buf_len` into `max_size` with plain `+=`.

Because `ri_data` originates from guest memory, the attacker controls the individual `buf_len` values. In release builds, overflowing `usize` addition wraps. That wrapped `max_size` is then used to choose the receive-buffer path and size the temporary buffer before later per-iovec memory validation occurs.

The reproducer confirms the broader claimed impact is overstated: valid guest memory cannot back arbitrarily huge buffers because memory growth is capped, and later copy/read helpers revalidate each iovec and fail with `Memviolation`. However, the narrower bug is reproduced: malformed `Memory64` iovecs can force `max_size` wraparound, leading `recv_from` to read into an undersized temporary buffer first and only fail later, instead of returning `Errno::Overflow` immediately.

## Why This Is A Real Bug
The syscall accepts attacker-controlled length metadata and performs arithmetic that can silently wrap in production builds. Even though later memory checks prevent the originally claimed successful oversized receive, the overflow still changes control flow and buffer sizing based on corrupted state. That is a real input-validation failure with observable behavior: invalid requests are processed with a wrapped smaller maximum rather than being rejected at the boundary where the overflow occurs.

## Fix Requirement
Replace unchecked accumulation of `max_size` with `checked_add` and return `Errno::Overflow` if the total iovec length cannot be represented in `usize`.

## Patch Rationale
The patch adds overflow-checked accumulation in `lib/wasix/src/syscalls/wasix/sock_recv_from.rs`, making the syscall fail closed at the point the aggregate iovec length exceeds `usize::MAX`. This matches the intended error model, prevents wrapped buffer sizing, and avoids progressing into `recv_from` with attacker-corrupted `max_size`.

## Residual Risk
None

## Patch
Patched in `057-unchecked-iovec-length-sum-can-wrap-max-size.patch`.