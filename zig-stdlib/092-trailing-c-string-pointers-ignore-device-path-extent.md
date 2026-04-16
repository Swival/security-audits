# Trailing C-string pointers ignore device-path extent

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/os/uefi/device_path.zig:751`

## Summary
`FilePathDevicePath.getPath` returns a sentinel `[*:0]const u16` derived from the bytes immediately after the 4-byte device-path header without validating that the node length includes any UTF-16 payload or that a terminating `u16` zero appears before the declared node extent ends. On malformed firmware-provided `FilePath` nodes, consumers can read past the record boundary into the following device-path node.

## Provenance
- Verified from the provided finding and reproduced locally with the supplied PoC summary
- Scanner source: https://swival.dev

## Preconditions
- Caller uses a `FilePath` device path with malformed trailing data

## Proof
- `getPath` in `lib/std/os/uefi/device_path.zig:751` pointer-casts `self + @sizeOf(FilePathDevicePath)` to `[*:0]const u16`.
- The accessor does not validate `self.length` against `@sizeOf(FilePathDevicePath)` plus any UTF-16 payload.
- The accessor does not verify that a zero `u16` terminator exists within the node's declared extent.
- Reproduction showed `fp.getPath()[0] == 0xff7f`, reading the following end-node `{ type = 0x7f, subtype = 0xff }` bytes as UTF-16, and `fp.getPath()[1] == 0x0004`, reading the end-node length field.
- This demonstrates out-of-bounds reads relative to the `FilePath` node's declared extent.

## Why This Is A Real Bug
UEFI device paths are firmware-sourced binary structures and cannot be assumed well-formed. Returning an unchecked sentinel pointer breaks the per-node bounds invariant: even a simple indexed read or terminator scan can consume bytes from the next node. The bug is independent of current in-tree call sites because the exported accessor itself exposes invalid memory semantics for malformed input.

## Fix Requirement
Change the accessor to return a length-bounded result only after validating that:
- `length` is at least `@sizeOf(FilePathDevicePath)`
- the trailing payload length is even and can contain UTF-16 code units
- a terminating zero `u16` exists within the declared node extent

## Patch Rationale
The patch replaces the unchecked trailing C-string pointer exposure with bounded parsing based on the device-path node length, rejecting malformed nodes that lack a valid in-bounds UTF-16 terminator. This preserves record-boundary safety while still supporting valid `FilePath` nodes.

## Residual Risk
None

## Patch
- Patch file: `092-trailing-c-string-pointers-ignore-device-path-extent.patch`
- Patched area: `lib/std/os/uefi/device_path.zig`
- Patch effect: removes unchecked out-of-extent trailing-string access and enforces in-bounds terminator validation before returning path data