# Truncated base-128 arc can overrun input

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/crypto/codecs/asn1/Oid.zig:58`
- `lib/std/crypto/codecs/asn1.zig:188`

## Summary
`decodeDer` accepts OBJECT IDENTIFIER payload bytes without validating that each base-128 arc terminates. `toDot` later scans continuation bytes for each arc and advances `j` while the high bit is set, but it does not ensure `j < encoded.len` before reading `encoded[j]`. A malformed OID ending in a continuation byte therefore causes out-of-bounds access during dot-string conversion.

## Provenance
- Verified from the provided reproducer and code-path analysis
- Reference: https://swival.dev

## Preconditions
- Caller invokes `toDot` on malformed OID bytes ending with a continuation byte

## Proof
A minimal DER payload `06 02 2a 80` reproduces the issue:
- `decodeDer` accepts the OBJECT IDENTIFIER and returns the raw payload slice `{ 0x2a, 0x80 }` from `lib/std/crypto/codecs/asn1.zig:188`
- `toDot` emits the first combined arc from `0x2a` as `1.2`
- It then begins scanning the next arc at `lib/std/crypto/codecs/asn1/Oid.zig:58`
- With `i = 1`, `encoded[1] == 0x80`, so the continuation-loop increments `j` to `2`
- The loop condition reads `encoded[2]` without a bounds check, overrunning the slice

In safety-checked builds this traps on bounds failure. In unchecked builds this is undefined behavior.

## Why This Is A Real Bug
The trigger is reachable from untrusted DER input accepted by the decoder, and the failing read occurs before any rejection of malformed arc encoding. This is not a theoretical parser strictness issue; it is a direct memory-safety failure in a public conversion path.

## Fix Requirement
Add a bounds check to the continuation-byte scan in `toDot` and return an error when an arc is truncated instead of reading past the end of the slice.

## Patch Rationale
The patch should reject unterminated base-128 arcs at the point of scan by checking bounds before each continuation-byte read. This preserves current behavior for valid OIDs, converts malformed trailing-continuation inputs into a structured error, and removes the out-of-bounds access.

## Residual Risk
None

## Patch
- Patch file: `080-truncated-base-128-arc-can-overrun-input.patch`
- Intended change: guard the `j` continuation scan in `lib/std/crypto/codecs/asn1/Oid.zig:58` and fail with an error on truncated base-128 arcs