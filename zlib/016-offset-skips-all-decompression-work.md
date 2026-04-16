# Offset skips all decompression work

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/dotzlib/DotZLib/Inflater.cs:49`

## Summary
`Inflater.Add(byte[], int, int)` uses `count` as the loop terminator while starting `inputIndex` at `offset`. For valid sliced input where `offset >= count` and `offset + count <= data.Length`, the loop never executes, so no compressed bytes are copied into zlib and no inflate work occurs.

## Provenance
- Verified finding reproduced from scanner output
- Scanner: Swival Security Scanner (`https://swival.dev`)

## Preconditions
- Caller passes valid `data`
- `offset >= count`
- `offset + count <= data.Length`

## Proof
- `Add()` initializes `total = count` and `inputIndex = offset` in `contrib/dotzlib/DotZLib/Inflater.cs:58`
- The work loop checks `inputIndex < total` in `contrib/dotzlib/DotZLib/Inflater.cs:64`
- For a valid call such as `Add(buf, 16, 8)`, `16 < 8` is false immediately, so the loop body is skipped
- As a result, neither `copyInput(...)` in `contrib/dotzlib/DotZLib/Inflater.cs:66` nor `inflate(...)` in `contrib/dotzlib/DotZLib/Inflater.cs:67` runs
- `contrib/dotzlib/DotZLib/CodecBase.cs:168` is the path that stages caller bytes into `_ztream`; because it is never reached, the supplied compressed slice is ignored
- The method then only updates `_checksum` from the existing stream state in `contrib/dotzlib/DotZLib/Inflater.cs:77`, and `Finish()` only flushes current state in `contrib/dotzlib/DotZLib/Inflater.cs:84`

## Why This Is A Real Bug
The public sliced-input API accepts an offset and count pair, and its bounds checks allow valid nonzero offsets. When `offset >= count`, the method silently discards the requested compressed bytes instead of inflating them. This causes input truncation, missing output, stale checksum state, and can later surface as stream corruption or inflate failure.

## Fix Requirement
Compute the exclusive end of the caller-provided slice as `offset + count`, iterate while `inputIndex < end`, and copy only the remaining `end - inputIndex` bytes into zlib on each pass.

## Patch Rationale
The patch replaces the incorrect loop bound derived from `count` alone with the actual slice end. This preserves existing validation and behavior for zero-offset callers while ensuring all valid sliced ranges are presented to `copyInput(...)` and `inflate(...)`.

## Residual Risk
None

## Patch
- Patched in `016-offset-skips-all-decompression-work.patch`
- Updated `contrib/dotzlib/DotZLib/Inflater.cs` to:
  - derive the loop terminator from `offset + count`
  - loop until the full requested slice is consumed
  - pass the remaining slice length to `copyInput(...)`