# Expand accepts forged local ZIP sizes for decompression

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/zip.d:858`
- `std/zip.d:1224`
- `std/zlib.d:261`

## Summary
`std.zip` parses member sizes from central-directory metadata, but `expand` later replaces `de._expandedSize` with `max(getUint(de.offset + 22), de.expandedSize)` using the untrusted local file header. A forged archive can therefore increase the requested decompression size after archive parsing and before extraction. That attacker-controlled size is passed into `std.zlib.uncompress`, which resizes the destination buffer to the supplied length before inflation completes, enabling oversized allocation attempts during reachable extraction.

## Provenance
- Reproduced from the verified finding and patch workflow against `std/zip.d`
- Scanner provenance: https://swival.dev

## Preconditions
- Attacker supplies a ZIP archive whose local file header advertises a larger uncompressed size than the central directory

## Proof
- Archive parsing records the central-directory size into `de._expandedSize`
- `expand` reads the local header size at `std/zip.d:858` and updates `de._expandedSize` to the larger of the local and central values instead of validating them
- `expand` then calls `uncompress(..., de.expandedSize, -15)` at `std/zip.d:1224`
- `std.zlib.uncompress` resizes the destination buffer to the caller-provided `destlen` immediately at `std/zlib.d:261`
- Reproducer archive values:
  - Central-directory `expandedSize = 5`
  - Local-header `expandedSize = 67108864`
- Observed runtime behavior:
  - Before `expand`, parsed member `expandedSize = 5`
  - After `expand`, member `expandedSize = 67108864`
  - Returned decompressed data length remains `5`
- This demonstrates that the forged local size directly controls the temporary allocation size even though the actual inflated payload is small

## Why This Is A Real Bug
The vulnerable path crosses a clear trust boundary: central-directory metadata is the archive-level record already used during parsing, while local-header metadata comes from attacker-controlled bytes inside the same file and is not validated for consistency before use. Because `std.zlib.uncompress` allocates based on the supplied destination length before finishing inflation, the mismatch is exploitable as memory over-allocation during normal extraction. The reproducer confirms the state transition and allocation-driving value change at runtime.

## Fix Requirement
Reject mismatched local and central uncompressed sizes before updating `de._expandedSize` or invoking decompression. Extraction must continue to use only validated size metadata.

## Patch Rationale
The patch enforces equality between the local-header and central-directory size fields instead of taking the larger value. This preserves the original parser trust decision, blocks attacker-controlled size inflation before decompression, and prevents `std.zlib.uncompress` from receiving a forged oversized destination length.

## Residual Risk
None

## Patch
- Patched file: `076-expand-trusts-local-header-sizes-for-decompression.patch`
- Change intent:
  - stop promoting `de._expandedSize` from the local header
  - validate local vs central size consistency before decompression
  - fail extraction on mismatch rather than allocating from attacker-supplied local metadata