# ZIP64 extra field parser overreads declared subfield

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/unzip.c:763`

## Summary
`unz64local_GetCurrentFileInfoInternal()` parses central-directory extra fields and, in the ZIP64 branch, conditionally reads up to 28 bytes of ZIP64 values based on sentinel header fields. Those reads are not bounded by the subfield's declared `dataSize` or the remaining extra-field budget. A crafted ZIP64 extra block therefore causes parsing to consume bytes beyond the declared subfield and into adjacent central-directory data while still returning success.

## Provenance
- Verified from the supplied reproducer and finding description
- Reference: https://swival.dev

## Preconditions
- Attacker controls ZIP central-directory extra field bytes

## Proof
A malformed archive declared a ZIP64 extra subfield with `dataSize = 0` while setting sentinel values that force ZIP64 expansion. During `unzGetCurrentFileInfo64()`, the parser:
- read `headerId` and `dataSize`
- entered the ZIP64 branch
- consumed `compressed_size`, `uncompressed_size`, `offset_curfile`, and `disk_num_start` from bytes located after the declared subfield
- advanced only by `dataSize`, not by the bytes actually read

The reproducer showed:
- `unzGetCurrentFileInfo64()` returned success
- parsed metadata fields were populated from attacker-controlled bytes placed in the file comment area
- subsequent comment bytes began with `50 4b 05 06` (`PK\x05\x06`), proving the parser had read through the comment into EOCD-adjacent data
- `unzOpenCurrentFile()` still succeeded and normal file content reads worked

## Why This Is A Real Bug
This is not a reject-only parser quirk. The malformed archive is accepted, and minizip uses attacker-controlled bytes outside the declared ZIP64 subfield as trusted metadata. That creates an out-of-bounds logical read across ZIP structure boundaries during normal archive enumeration/open and can misparse central-directory state from unrelated adjacent records.

## Fix Requirement
Before each ZIP64 value read, validate that the required bytes remain within both:
- the current subfield's declared `dataSize`
- the total remaining extra-field byte budget

On failure, stop parsing and return an error before consuming out-of-subfield data.

## Patch Rationale
The patch in `003-zip64-extra-field-parser-reads-past-declared-field.patch` adds per-read bounds checks in the ZIP64 extra-field parser so each 64-bit or 32-bit expansion is allowed only when enough bytes remain in the declared subfield and enclosing extra field. This preserves valid ZIP64 parsing while preventing cross-subfield and cross-structure reads.

## Residual Risk
None

## Patch
- Patch file: `003-zip64-extra-field-parser-reads-past-declared-field.patch`
- Patched location: `contrib/minizip/unzip.c:763`