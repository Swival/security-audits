# Zero-length node causes infinite traversal

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/os/uefi/protocol/device_path.zig:33`

## Summary
`size(self: *const DevicePath)` traverses a caller-supplied UEFI device-path by repeatedly calling `next()`. Before the fix, `next()` advanced by `self.length` for any non-end node without validating that `length` was non-zero. A malformed non-end node with `length == 0` therefore returned the same pointer, causing `size()` to loop forever and hang reachable callers such as `createFileDevicePath()`.

## Provenance
- Reproduced from the provided finding and source review
- Public API reachability confirmed in `lib/std/os/uefi/protocol/device_path.zig`
- Scanner origin: [Swival Security Scanner](https://swival.dev)

## Preconditions
- Parsed device path contains a non-end node with `length == 0`

## Proof
- `size()` initializes `node` from the caller-provided `*const DevicePath` and loops until `next()` returns `null`.
- `next()` returns `null` only for an end-entire node; otherwise it computes `bytes + self.length`.
- For a non-end node with `length == 0`, `next()` returns the same address as `self`.
- The loop in `size()` therefore never makes progress and never terminates.
- Reproduction used a minimal Zig program with `.type = .media`, non-end `subtype`, and `.length = 0`; `next()` returned the same pointer and `zig run` under `timeout 2s` exited with status `124`, confirming the hang.

## Why This Is A Real Bug
The bug is directly reachable through a public API that accepts arbitrary caller-controlled device-path pointers and performs no structural validation before traversal. A zero-length non-end node is sufficient to trigger an infinite loop, producing a reliable denial of service in any consumer that measures or copies such a path.

## Fix Requirement
Reject or stop on zero-length non-end nodes before advancing traversal so that malformed input cannot cause a non-progressing loop.

## Patch Rationale
The patch adds a progress guard in device-path traversal so zero-length non-end nodes are not advanced through as if valid. This enforces the minimal safety invariant required by `size()` and callers that depend on it, preventing infinite traversal while preserving normal behavior for well-formed paths.

## Residual Risk
None

## Patch
- Patch file: `093-zero-length-node-causes-infinite-traversal.patch`
- Patched location: `lib/std/os/uefi/protocol/device_path.zig`
- Effect: prevents `size()` from looping forever on malformed device-path nodes with `length == 0` by refusing zero-length advancement for non-end nodes