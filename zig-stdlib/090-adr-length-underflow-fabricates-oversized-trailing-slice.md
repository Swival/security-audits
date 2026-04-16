# ADR length underflow fabricates oversized trailing slice

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/std/os/uefi/device_path.zig:182`

## Summary
`AdrDevicePath.adrs()` derives a trailing `[]const u32` length from `self.length` without first validating that the UEFI node length is at least the fixed header size. When `self.length < 4`, the `u16` subtraction underflows. In checked builds this aborts on integer overflow; in unchecked release builds it wraps and fabricates an oversized slice extending past the backing struct.

## Provenance
- Verified by local reproduction against the reported code path
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- Caller invokes `adrs()` on `AdrDevicePath` with `length < 4`

## Proof
- `AdrDevicePath.length` is an unchecked `u16` parsed from a device-path record.
- At `lib/std/os/uefi/device_path.zig:182`, `adrs()` computes `entries = (self.length - 4) / @sizeOf(u32)` and returns `(&self.adr)[0..entries]`.
- With `length = 3` in a default checked build, the subtraction traps with `panic: integer overflow`.
- With `length = 3` in `-O ReleaseFast`, the subtraction wraps as `u16`: `3 - 4 = 65535`.
- `entries` then becomes `65535 / 4 = 16383`, so the function returns a `[]const u32` of length `16383` starting at `&self.adr`.
- That slice exceeds both the 4-byte `adr` field and the 8-byte struct backing memory, enabling out-of-bounds reads by consumers.

## Why This Is A Real Bug
The method accepts attacker-controlled structural metadata and uses it to construct a trusted slice. The failure mode is build-dependent but incorrect in both cases: checked builds crash on malformed input, while unchecked builds produce a forged oversized slice. The API contract therefore lacks required length validation before pointer-derived slice construction.

## Fix Requirement
Validate `self.length >= 4` before performing the subtraction, and only derive the trailing entry count from a validated node length.

## Patch Rationale
The patch adds an explicit guard for undersized ADR nodes before subtracting the fixed portion of the record. This removes the underflow path, prevents panic-on-malformed-input in checked builds, and blocks oversized slice fabrication in unchecked builds.

## Residual Risk
None

## Patch
```diff
--- a/lib/std/os/uefi/device_path.zig
+++ b/lib/std/os/uefi/device_path.zig
@@
     pub fn adrs(self: *const AdrDevicePath) []const u32 {
+        if (self.length < 4) return &.{};
         const entries = (self.length - 4) / @sizeOf(u32);
         return (&self.adr)[0..entries];
     }
```