# Trailer CRC Validation Missing In Joined Members

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzjoin.c:381`

## Summary
`gzjoin` reads each gzip member trailer CRC directly from attacker-controlled input and combines it into the final output CRC without validating it against the actual inflated member data. A forged member trailer therefore propagates into the joined output trailer and causes downstream integrity verification to fail.

## Provenance
- Verified finding reproduced and patched from scanner report
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- Attacker can supply a gzip member with a forged trailer CRC

## Proof
- In `examples/gzjoin.c:381`, the member trailer CRC is read via `bget4(in)`.
- That value is used as input to `crc32_combine(*crc, ..., len)` without first checking it against a CRC computed over the inflated member bytes.
- `gzcopy()` inflates members to locate block boundaries and determine length, but previously did not validate the member trailer CRC.
- Reproduction showed `gzjoin` accepted a forged member and produced `out.gz` whose trailer CRC matched the forged value rather than the true concatenated plaintext CRC.
- Downstream consumers rejected the result: `gzip -t` failed and Python `gzip` raised `BadGzipFile: CRC check failed`.

## Why This Is A Real Bug
The bug is externally observable and security-relevant because integrity metadata in the emitted gzip file becomes attacker-influenced and incorrect. Even if `gzjoin` is an example utility, it emits malformed output that predictably fails validation in standard consumers. The fault is reachable on every processed member because trailer parsing is mandatory.

## Fix Requirement
Compute each member CRC while inflating and reject the member if the computed CRC does not match the trailer CRC before combining it into the output CRC.

## Patch Rationale
The patch updates `examples/gzjoin.c` to maintain a per-member computed CRC during inflation, compare it to the trailer CRC read from input, and abort processing on mismatch. This prevents forged trailer values from contaminating the combined output trailer and ensures only validated member CRCs are used.

## Residual Risk
None

## Patch
- Patch file: `011-trailer-crc-is-taken-from-input-without-validation.patch`
- Fixes `examples/gzjoin.c` by validating each member trailer CRC before calling `crc32_combine()` and emitting the final gzip trailer.