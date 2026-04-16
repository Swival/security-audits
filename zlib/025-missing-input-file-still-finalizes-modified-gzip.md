# Missing final append input still commits rewritten gzip

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzappend.c:338`
- `examples/gzappend.c:426`
- `examples/gzappend.c:437`

## Summary
When the final append operand is missing or unreadable, `gztack()` warns but continues with `fd` left at `0`. For the last operand, EOF on that descriptor causes `deflate(..., Z_FINISH)` to execute and the gzip trailer to be rewritten, even though no bytes from the requested file were appended. Because `gzscan()` already cleared the prior last-block bit, the tool silently commits a modified archive while reporting success.

## Provenance
- Verified from the provided reproducer and source analysis in `examples/gzappend.c`
- Independent reproduction performed against the repository version of `gzappend`
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- The last CLI append file is missing or unreadable
- Standard input is at EOF or otherwise provides no replacement data

## Proof
A confirmed reproduction shows the bug is reachable and causes observable archive mutation:
- `main()` passes the user-controlled final append path into `gztack()`
- At `examples/gzappend.c:338`, `open(name)` failure only emits a warning and leaves `fd = 0`
- With the final operand, the read loop reaches EOF immediately, making `last && len == 0` true at `examples/gzappend.c:426`, which selects `Z_FINISH`
- `gztack()` then writes a new trailer unconditionally when `last` is true at `examples/gzappend.c:437`
- Reproduction result: `/tmp/gzappend file.gz missing.txt </dev/null` exits `0`, emits warnings, preserves decompressed payload `base-data\n`, but changes the gzip byte stream and file length

## Why This Is A Real Bug
This is a real integrity failure because the program mutates persistent output while omitting the user-requested final input, and it does so without failing the operation. The resulting gzip remains decompressible, which makes the corruption silent at the semantic level the tool is expected to preserve: “append this file” was not satisfied, yet the archive was rewritten and finalized as if it were.

## Fix Requirement
The implementation must not finalize or rewrite the gzip trailer when the final requested input could not be opened. The operation should fail for that case, or otherwise suppress finishing logic so the archive is left unmodified.

## Patch Rationale
The patch should make missing final input a hard stop before any `Z_FINISH` path can be taken. That directly prevents the unintended trailer rewrite and preserves archive integrity when the requested append source is unavailable. This approach matches user expectation and avoids silent partial success semantics for the final operand.

## Residual Risk
None

## Patch
Patched in `025-missing-input-file-still-finalizes-modified-gzip.patch`. The fix prevents the last append operand from falling through to EOF-driven finalization after `open()` failure, so `gzappend` no longer rewrites and commits a modified gzip when the requested final file is missing.