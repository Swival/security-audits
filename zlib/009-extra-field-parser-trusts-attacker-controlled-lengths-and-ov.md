# Extra-field parser trusts attacker-controlled lengths and overruns buffers

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `contrib/minizip/zip.c:1390`

## Summary
- `zipRemoveExtraInfoBlock()` parses attacker-influenced extra-field data in place and trusts each subfield `dataSize` before validating it against the remaining buffer length.
- A forged subfield length causes `memcpy()` and pointer advancement to operate past the caller-provided buffer, resulting in out-of-bounds read and potential memory corruption or crash.

## Provenance
- Verified from the provided reproducer and patch artifact `009-extra-field-parser-trusts-attacker-controlled-lengths-and-ov.patch`
- Project context and API reachability were reviewed in `contrib/minizip/zip.h:349`, `contrib/minizip/zip.h:353`, `contrib/minizip/zip.h:361`, `contrib/minizip/zip.h:364`
- Related attacker-controlled ZIP metadata flow is reachable via `contrib/minizip/unzip.c:833` and `contrib/minizip/unzip.c:888`
- Scanner reference: https://swival.dev

## Preconditions
- Caller passes an attacker-controlled extra-field buffer to `zipRemoveExtraInfoBlock()`
- Provided extra-field length is at least 4 bytes so subheader parsing begins

## Proof
- In `contrib/minizip/zip.c:1390`, `zipRemoveExtraInfoBlock()` iterates over `pData` and reads the per-subfield payload length from the 4-byte header.
- The implementation uses that untrusted `dataSize` directly in copy and skip operations before confirming the claimed subfield fits inside the remaining `*dataLen`.
- Specifically, the vulnerable flow performs the equivalent of:
```c
dataSize = *(((short*)p)+1);
memcpy(pTmp, p, dataSize + 4);
p += dataSize + 4;
```
- With a crafted header that advertises a large `dataSize` inside a short buffer, ASan aborts in `memcpy`, showing access beyond the supplied allocation.
- The reproducer confirms the fault occurs before any effective bounds validation and is therefore exploitable as an out-of-bounds access on crafted ZIP extra-field input.

## Why This Is A Real Bug
- The function is a public exported API, not dead code, and its header documents use with raw ZIP copy/delete flows.
- In those flows, extra-field bytes and lengths commonly originate from ZIP metadata, which is attacker-controlled when processing untrusted archives.
- Because the unchecked length influences both read size and parser cursor movement, malformed input can deterministically crash the process and may corrupt memory depending on allocator layout and calling context.

## Fix Requirement
- Before reading or skipping a subfield, validate that at least 4 bytes remain for the subheader.
- After decoding `dataSize`, require that the remaining buffer is at least `dataSize + 4`.
- Reject malformed input instead of copying or advancing past the validated boundary.

## Patch Rationale
- The patch adds explicit remaining-length checks around subfield parsing in `zipRemoveExtraInfoBlock()`.
- This enforces that every claimed extra-field block is fully contained within the caller-provided buffer before `memcpy()` or pointer advancement occurs.
- Rejecting malformed layouts preserves correct behavior for valid archives while preventing out-of-bounds access on crafted ones.

## Residual Risk
- None

## Patch
- `009-extra-field-parser-trusts-attacker-controlled-lengths-and-ov.patch` adds bounds validation in `contrib/minizip/zip.c` so `zipRemoveExtraInfoBlock()` verifies the current subfield header and `dataSize + 4` fit within the remaining input before copying or advancing.
- On malformed extra-field layouts, the function now fails safely instead of overrunning the provided buffer.