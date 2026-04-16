# Extra-field parser overruns on forged subblock length

## Classification
High severity validation gap
Confidence: certain

## Affected Locations
- `contrib/minizip/zip.c:1390`
- `contrib/minizip/zip.h:349`
- `contrib/minizip/zip.h:353`
- `contrib/minizip/zip.h:361`
- `contrib/minizip/zip.h:364`
- `contrib/minizip/unzip.c:833`
- `contrib/minizip/unzip.c:888`

## Summary
`zipRemoveExtraInfoBlock()` trusts the attacker-controlled 16-bit `dataSize` field from each extra-field subheader and uses it to advance and copy data before validating that the claimed subblock fits inside the caller-supplied buffer. A crafted extra field can therefore drive out-of-bounds reads and oversized `memcpy` operations.

## Provenance
Verified by reproduction with AddressSanitizer and patched locally from the supplied finding and reproducer details. External scanner reference: https://swival.dev

## Preconditions
Caller passes an attacker-controlled extra-field buffer with length at least 4 bytes into `zipRemoveExtraInfoBlock()`.

## Proof
In `zipRemoveExtraInfoBlock()` at `contrib/minizip/zip.c:1390`, the parser reads the subblock size from the current cursor:

```c
dataSize = *(((short*)p)+1);
```

It then consumes that untrusted length immediately:

```c
if (zipShort(p) != sHeader)
{
    memcpy(pTmp, p, dataSize + 4);
    pTmp += dataSize + 4;
}
p += dataSize + 4;
```

No check ensures `dataSize + 4` bytes remain within `*dataLen`. The reproduced ASan crash shows `memcpy` reading far beyond the provided 4-byte allocation after a forged length is supplied, confirming the unchecked length is used before any bounds validation.

## Why This Is A Real Bug
This helper is a public API exposed in `contrib/minizip/zip.h:349`, and its documentation explicitly directs callers to pass ZIP extra-field buffers during RAW copy/delete workflows. Those extra fields are naturally sourced from ZIP metadata parsed by `unzip`, where both the extra-field length and contents are attacker-controlled. The bug is therefore reachable in realistic library integrations and can cause process termination or memory corruption when handling crafted ZIP input.

## Fix Requirement
Before processing each subblock, validate that at least 4 bytes remain for the subheader and that the claimed `dataSize + 4` does not exceed the remaining buffer. Reject malformed input instead of copying or skipping past the end.

## Patch Rationale
The patch adds per-subblock bounds checks in `zipRemoveExtraInfoBlock()` before any `memcpy` or pointer advancement based on `dataSize`. If the remaining buffer is too short for the subheader or the claimed payload length, the function fails early rather than dereferencing or copying beyond `pData`. This directly enforces the parser invariant required by the ZIP extra-field format and preserves existing behavior for well-formed buffers.

## Residual Risk
None

## Patch
Patched in `009-extra-field-parser-trusts-attacker-controlled-lengths-and-ov.patch`.