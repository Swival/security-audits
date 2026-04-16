# USB WWID length underflow overreads serial buffer

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/os/uefi/device_path.zig:366`

## Summary
`UsbWwidDevicePath.serial_number()` trusts the on-structure `length` field and subtracts `@sizeOf(UsbWwidDevicePath)` without first ensuring the node is large enough. When `length < 10`, the `u16` subtraction underflows. In safety-checked builds this traps; in optimized builds it wraps and produces a huge UTF-16 slice length, causing an out-of-bounds read past the serial buffer.

## Provenance
- Verified from the reported finding and reproduction against the Zig UEFI device-path implementation
- Public entry points in `lib/std/os/uefi/protocol/device_path.zig:84` and `lib/std/os/uefi/protocol/device_path.zig:102` permit reaching the typed USB WWID node based on type/subtype alone
- Reference: https://swival.dev

## Preconditions
- A `UsbWwidDevicePath` instance has `length` less than `@sizeOf(UsbWwidDevicePath)` (10 bytes)

## Proof
- `serial_number()` computes `(self.length - @sizeOf(UsbWwidDevicePath)) / 2`
- `self.length` is a `u16`, so for `length = 8` the subtraction underflows
- In debug/safe builds, Zig aborts with `panic: integer overflow`
- In `-O ReleaseFast`, the subtraction wraps, yielding `65534`, then `/ 2` yields `32767`
- The function then returns a UTF-16 slice beginning immediately after the 10-byte header with length `32767`, which extends far beyond the backing object and is readable by callers
- This reproduces as a real out-of-bounds read in optimized builds

## Why This Is A Real Bug
The malformed node is reachable through public UEFI device-path parsing APIs that only discriminate on node type and subtype, not minimum node size. Because the vulnerable method is public and directly uses attacker-controlled length metadata, a crafted device-path node can trigger either a deterministic crash in checked builds or memory disclosure via overread in optimized builds. The behavior is not theoretical; it was reproduced in both execution modes.

## Fix Requirement
Validate `self.length >= @sizeOf(UsbWwidDevicePath)` before performing the subtraction in `serial_number()`. If the node is undersized, return an empty slice or an error instead of deriving a serial length from wrapped arithmetic.

## Patch Rationale
The patch adds an explicit lower-bound check on `length` before subtracting the struct header size. This removes the underflow condition in all build modes and guarantees any returned UTF-16 slice length is derived only from non-wrapped, structurally valid node sizes. The change is narrowly scoped to the vulnerable accessor and matches the reproduced failure mode exactly.

## Residual Risk
None

## Patch
- Patch file: `091-usb-wwid-length-underflow-overreads-serial-buffer.patch`
- Intended change: guard `UsbWwidDevicePath.serial_number()` in `lib/std/os/uefi/device_path.zig` against `length < @sizeOf(UsbWwidDevicePath)` before computing the serial slice length