# Trailer CRC accepted from input without validation

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `examples/gzjoin.c:381`

## Summary
`gzcopy()` reads each member trailer CRC directly from attacker-controlled input with `bget4(in)` and uses that value in `crc32_combine()` without first validating it against the actual inflated member data. A forged member CRC therefore propagates into the emitted joined gzip trailer, causing `gzjoin` to produce output with incorrect integrity metadata.

## Provenance
- Verified finding reproduced and patched from Swival Security Scanner output: https://swival.dev
- Reproducer confirmed downstream failure with `gzip -t` and Python `gzip` reporting CRC mismatch on the joined output.

## Preconditions
- Attacker can supply a gzip member with a forged trailer CRC.

## Proof
- In `examples/gzjoin.c:381`, the member trailer CRC is read from input via `bget4(in)`.
- That untrusted value is passed into `crc32_combine(*crc, ..., len)` without comparison to a CRC computed while inflating the member.
- `gzcopy()` inflates to locate block boundaries and determine length, but before the patch it did not validate the member trailer CRC.
- Reproduction showed `gzjoin` accepted a forged member, emitted `out.gz`/joined output with the forged CRC folded into the final trailer, and downstream consumers rejected the result with CRC errors.

## Why This Is A Real Bug
The output gzip trailer is intended to authenticate the concatenated plaintext. If `gzjoin` trusts a forged per-member trailer CRC, it can emit a gzip file whose integrity metadata is objectively false even though the compressed payload is otherwise valid. This is externally observable and breaks downstream verification and decompression workflows, so the issue is not theoretical or merely cosmetic.

## Fix Requirement
Compute each member CRC while inflating and reject the member if the computed CRC does not match the trailer CRC before combining it into the final output CRC.

## Patch Rationale
The patch updates `gzcopy()` to maintain a running CRC across the inflated member bytes, reads the stored trailer CRC, and compares the two values before calling `crc32_combine()`. This ensures only validated member CRCs contribute to the final joined trailer and converts forged trailers into an explicit error instead of silently propagating corrupted integrity metadata.

## Residual Risk
None

## Patch
- Patch file: `011-trailer-crc-is-taken-from-input-without-validation.patch`
- Patched logic: `examples/gzjoin.c`
- Behavior change: forged member trailer CRCs are now rejected during processing instead of being trusted and incorporated into the output trailer.