# 64-bit pointer cast breaks checksum updates

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/ChecksumImpl.cs:116`
- `contrib/dotzlib/DotZLib/ChecksumImpl.cs:187`

## Summary
`CRC32Checksum.Update` and `AdlerChecksum.Update` pin a managed `byte[]` and convert the pinned pointer with `IntPtr.ToInt32()` before calling native zlib. On a 64-bit runtime, that conversion can throw when the pinned address does not fit in 32 bits, causing checksum updates to fail before entering zlib.

## Provenance
- Verified from reproduced behavior and source review
- Scanner: https://swival.dev

## Preconditions
- 64-bit runtime
- Invocation of `CRC32Checksum.Update` or `AdlerChecksum.Update`
- Pinned array address outside the signed 32-bit range

## Proof
`CRC32Checksum.Update` passes `hData.AddrOfPinnedObject().ToInt32() + offset` into the native `crc32` P/Invoke at `contrib/dotzlib/DotZLib/ChecksumImpl.cs:116`. `AdlerChecksum.Update` does the same for `adler32` at `contrib/dotzlib/DotZLib/ChecksumImpl.cs:187`.

On 64-bit runtimes, `IntPtr.ToInt32()` throws `OverflowException` if the native pointer value exceeds the 32-bit signed range. The reproduced behavior confirms the exception occurs before zlib is called, so the failure mode is a reachable compatibility and availability break in checksum calculation rather than silent native reads from a truncated address.

## Why This Is A Real Bug
The affected methods are public checksum update paths and remain loadable in modern 64-bit processes. There is no source-level platform guard preventing these calls on x64. As a result, valid checksum operations can fail nondeterministically based on heap placement, making the API unreliable on 64-bit runtimes.

## Fix Requirement
Change the native buffer parameter type to `IntPtr` and compute `offset` with pointer-sized arithmetic instead of `ToInt32()`.

## Patch Rationale
Using `IntPtr` preserves the full pinned address on both 32-bit and 64-bit runtimes. Applying `offset` via pointer-sized addition removes the overflow-prone narrowing conversion while keeping the native call contract intact.

## Residual Risk
None

## Patch
Patched in `012-pinned-buffer-pointer-truncated-to-32-bit-in-crc32-p-invoke.patch`.