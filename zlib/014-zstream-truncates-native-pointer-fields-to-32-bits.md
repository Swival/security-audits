# ZStream uses 32-bit managed fields for native pointers

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/DotZLib.cs:37`

## Summary
`ZStream` models native `z_stream` for P/Invoke, but several native pointer fields are declared as 32-bit `uint` in managed code. On 64-bit zlib builds, this makes the managed struct smaller than the native struct and breaks field alignment. As reproduced, initialization fails immediately on 64-bit targets because the wrapper passes the wrong `z_stream` size to zlib.

## Provenance
- Reported from verified finding reproduction
- Reproduced against the committed sources
- Scanner reference: `https://swival.dev`

## Preconditions
- 64-bit zlib build with pointer-sized `z_stream` fields
- Managed wrapper using `ZStream` from `contrib/dotzlib/DotZLib/DotZLib.cs`

## Proof
The managed `ZStream` definition at `contrib/dotzlib/DotZLib/DotZLib.cs:37` declares native pointer-bearing fields such as `state`, `zalloc`, `zfree`, and `opaque` as `uint`. On 64-bit ABIs these are 8-byte fields in native `z_stream`, but only 4 bytes in the managed layout.

Reproduction established:
- On LP64, native `z_stream` is 112 bytes while the managed layout derived from `DotZLib.cs` is 68 bytes.
- On Win64/LLP64, native `z_stream` is 88 bytes while the same managed layout remains 68 bytes.

Because the wrapper passes `Marshal.SizeOf(_ztream)` into zlib init, the size cannot match native `sizeof(z_stream)` on those targets. Instantiating `new Deflater(...)` or `new Inflater()` against a 64-bit zlib build causes init to fail with `Z_VERSION_ERROR`, surfacing as `ZLibException` from `contrib/dotzlib/DotZLib/Deflater.cs:42` or `contrib/dotzlib/DotZLib/Inflater.cs:41`.

## Why This Is A Real Bug
This is a concrete ABI mismatch, not a theoretical concern. The native library validates the caller-supplied stream struct size during initialization, and the reproduced behavior shows the mismatch is observable and user-facing on 64-bit builds. Compression and decompression become unusable in that environment.

## Fix Requirement
Change all managed fields that represent native pointers in `ZStream` to `IntPtr` so the managed layout tracks platform pointer width. Remove any fixed 4-byte assumptions that would preserve the incorrect 32-bit layout on 64-bit targets.

## Patch Rationale
The patch updates the managed `ZStream` definition in `contrib/dotzlib/DotZLib/DotZLib.cs` so native pointer fields use pointer-sized managed types. That restores the correct platform-dependent struct size and field alignment, allowing `Marshal.SizeOf` to match native `sizeof(z_stream)` on supported 64-bit builds and letting zlib initialization succeed.

## Residual Risk
None

## Patch
- `014-zstream-truncates-native-pointer-fields-to-32-bits.patch`