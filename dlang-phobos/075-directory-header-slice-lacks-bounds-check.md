# Directory header slice lacks bounds check

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `std/zip.d:634`

## Summary
- `new ZipArchive(buffer)` parses central-directory entries using fixed-width reads before confirming the full central-file-header fits inside the declared directory region.
- A truncated attacker-controlled central-directory entry can therefore trigger an unchecked slice/read during archive open, causing process abort instead of a handled `ZipException`.

## Provenance
- Verified from the supplied reproducer and patch context in `std/zip.d`
- Reference: Swival Security Scanner, `https://swival.dev`

## Preconditions
- Attacker controls ZIP bytes with a truncated central-directory entry

## Proof
- EOCD parsing sets `i = directoryOffset` and enters the central-directory loop.
- Before validating that `i + centralFileHeaderLength <= directoryOffset + directorySize`, the parser performs central-header access from `_data`, including the 4-byte signature check and later fixed-offset field reads such as `getUint(i + 24)`.
- A minimal malformed archive with `PK\x01\x02` at offset 0 and an EOCD claiming `directoryCount=1`, `directorySize=4`, `directoryOffset=0` reproduces the issue.
- Constructing `new ZipArchive(...)` on that input aborts with `core.exception.ArraySliceError: slice [24 .. 28] extends past source array of length 26`, confirming an out-of-bounds access before validation.

## Why This Is A Real Bug
- The failure is reachable on archive open from attacker-controlled input.
- The exception is a runtime bounds failure, not the library's expected validation error path.
- This yields a reliable denial of service against consumers that process untrusted ZIP data.

## Fix Requirement
- Validate that the full central-file-header is within `directoryOffset + directorySize` before any central-header slice or field read.

## Patch Rationale
- The patch adds an early bounds check for `i + centralFileHeaderLength` against the declared directory end before signature comparison and header field extraction.
- This moves malformed truncated entries onto the existing invalid-archive handling path and prevents unchecked runtime slicing/reads.

## Residual Risk
- None

## Patch
- `075-directory-header-slice-lacks-bounds-check.patch` adds the missing pre-read bounds validation in `std/zip.d` so truncated central-directory entries raise a handled archive error instead of aborting.