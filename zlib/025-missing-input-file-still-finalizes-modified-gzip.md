# Missing final input silently commits a rewritten gzip

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzappend.c:338`
- `examples/gzappend.c:426`
- `examples/gzappend.c:437`

## Summary
When the last append operand is missing or unreadable, `gztack()` warns but continues with `fd = 0`. With stdin at EOF, the append loop reaches `deflate(..., Z_FINISH)` and then rewrites the gzip trailer because `last` remains true. Since `gzscan()` already cleared the prior last-block bit, the tool exits successfully after mutating and re-finalizing the archive without appending the requested file.

## Provenance
- Reproduced from the verified report and patch preparation workflow
- Reference: https://swival.dev

## Preconditions
- The final CLI append path is missing or unreadable
- Stdin is available and yields EOF, such as `</dev/null>`

## Proof
A working reproduction was performed by compiling `examples/gzappend.c` against the repository zlib sources and running the tool with a valid gzip plus a missing final append argument.
- Initial state: gzip containing `base-data\n`
- Command: `/tmp/gzappend file.gz missing.txt </dev/null`
- Observed behavior:
  - Exit status was `0`
  - Only warnings were emitted on stderr
  - The gzip still decompressed to `base-data\n`
  - The archive bytes changed: digest changed and file size changed from 30 to 31 bytes

This matches the code path:
- `open(name)` failure at `examples/gzappend.c:338` only warns and leaves processing active
- `last && len == 0` reaches `Z_FINISH` at `examples/gzappend.c:426`
- Trailer rewrite occurs unconditionally for `last` at `examples/gzappend.c:437`

## Why This Is A Real Bug
The tool promises to append user-specified input to an existing gzip. In this failure mode it instead modifies the gzip structure and commits a new finalized archive while omitting the requested final input, yet returns success. That is a concrete integrity failure: the output file is silently changed to a different byte sequence than before, despite the append operation not succeeding.

## Fix Requirement
Abort processing when the final append input cannot be opened, or otherwise prevent `Z_FINISH` and trailer rewrite after any skipped final input.

## Patch Rationale
The patch in `025-missing-input-file-still-finalizes-modified-gzip.patch` makes the missing final input a hard failure in `examples/gzappend.c`, preventing the append loop from finalizing the deflate stream or rewriting the gzip trailer when the requested last file was not actually processed. This preserves archive bytes on the reproduced path and aligns program success with real append completion.

## Residual Risk
None

## Patch
- Patch file: `025-missing-input-file-still-finalizes-modified-gzip.patch`
- Target: `examples/gzappend.c`
- Effect: stop successful finalization when the last append operand cannot be opened, eliminating the silent rewritten-gzip outcome reproduced here