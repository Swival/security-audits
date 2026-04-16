# Non-hex input is accepted and emitted

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:18`

## Summary
`contrib/puff/bin-writer.c` reads two stdin characters into a hex byte buffer and parses them with `strtol(..., 16)`, but never verifies that both characters were consumed. As a result, malformed byte pairs are accepted and still emitted via `fwrite`, allowing non-hex input to silently produce output bytes.

## Provenance
- Verified finding reproduced locally from the provided report
- Scanner source: https://swival.dev

## Preconditions
- `stdin` contains a non-hex character in a two-character byte pair

## Proof
- Input bytes are copied directly from `getchar()` into the two-byte parse buffer in `contrib/puff/bin-writer.c:15` and `contrib/puff/bin-writer.c:16`.
- The pair is parsed with `strtol(hexStr, &endptr, 16)` in `contrib/puff/bin-writer.c:19`.
- The code does not require `endptr == hexStr + 2` before writing the parsed value in `contrib/puff/bin-writer.c:20`.
- Reproduced outcomes:
  - `printf '4G ' | /tmp/bin-writer | od -An -t x1` emits `04`
  - `printf 'G4 ' | /tmp/bin-writer | od -An -t x1` emits `00`
  - `printf 'zz ' | /tmp/bin-writer | od -An -t x1` emits `00`

## Why This Is A Real Bug
The program's purpose is to convert hexadecimal text into binary bytes. Accepting partial or zero-length parses violates that contract and causes malformed input to be silently transformed into output data instead of being rejected. This directly corrupts the produced binary stream and makes invalid input indistinguishable from valid encoded bytes at the output boundary.

## Fix Requirement
Reject any byte pair unless parsing consumes exactly both hex characters, i.e. require `endptr == hexStr + 2` before calling `fwrite`.

## Patch Rationale
The patch in `031-non-hex-input-is-accepted-and-emitted.patch` adds strict post-parse validation so only complete two-digit hexadecimal pairs are emitted. This closes both partial-parse cases like `4G` and zero-digit cases like `G4` or `zz`, aligning behavior with the tool's expected input format and preventing silent data corruption.

## Residual Risk
None

## Patch
- `031-non-hex-input-is-accepted-and-emitted.patch` enforces full-consumption validation of each parsed byte pair before writing output, rejecting malformed non-hex input instead of emitting a derived byte.