# Chunked decoder truncates trailing data after split padded quartet

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/base64.d:1037`

## Summary
`Base64.decoder` for chunked input can silently drop valid trailing encoded data when a padded quartet is split across chunk boundaries and `Decoder.doDecoding` concatenates enough chunks to reach a multiple of four. The concatenated buffer is passed to `decode`, which stops at the first padded quartet and returns without rejecting subsequent non-padding input.

## Provenance
- Verified from the supplied reproducer and source analysis
- Scanner origin: https://swival.dev

## Preconditions
- The chunked Base64 decoder consumes split encoded chunks
- A padded quartet is split across chunk boundaries
- Additional non-padding encoded data follows within the concatenated decode window
- Build mode disables the relevant contract check, such as release-style builds

## Proof
A minimal reproducer using the documented range-of-chunks API triggers truncation:

```d
import std.base64, std.array, std.stdio;

void main() {
    auto out = Base64.decoder([['e','y','0'], ['=','P','P','8','=']]).array;
    writeln(out);
}
```

Observed behavior in `ldc2 -release`:
- Output decodes only the first padded quartet, yielding bytes `7B2D` (`"{-"`)
- The trailing `PP8=` data is silently discarded

Root cause at `std/base64.d:1037`:
- `Decoder.doDecoding` concatenates chunks until total length is divisible by 4
- The combined slice is sent to `decode(data, buffer_)`
- `decode` returns when `v3` or `v4` is padding, but does not enforce that padding occurs only in the final quartet of the provided input
- Remaining non-padding input after that early padding boundary is ignored

The originally proposed sample `[['e','y','0','='], ['P','P','8','=']]` does not reproduce because no concatenation occurs; each 4-byte chunk is decoded independently.

## Why This Is A Real Bug
This is reachable through the documented chunked-decoder API and causes observable data loss in release-style builds. The behavior violates decoder integrity expectations: valid trailing encoded input is neither decoded nor rejected. In checked builds, the same path fails an internal postcondition, confirming the implementation invariant is broken rather than the input being intentionally unsupported.

## Fix Requirement
Reject concatenated chunk buffers whenever padding appears before the final quartet or before any remaining non-padding encoded input. The chunked decoder must either decode the full provided window or fail explicitly; it must never silently truncate.

## Patch Rationale
The patch adds validation on the concatenated decode path so an early padding boundary is treated as invalid input instead of allowing partial decode success. This preserves existing behavior for valid chunk boundaries while preventing silent loss of trailing data and aligning release behavior with the invariant already enforced by contracts.

## Residual Risk
None

## Patch
- Patch file: `032-chunked-decoder-drops-data-after-early-padding-boundary.patch`
- Patched area: `std/base64.d`
- Effect: converts the silent truncation case into explicit rejection when concatenated chunk data contains padding before remaining encoded input