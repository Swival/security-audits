# Block checksums are parsed but never verified

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/std/compress/xz/Decompress.zig:119`
- `lib/std/compress/xz/Decompress.zig:301`

## Summary
`std.compress.xz.Decompress` records the stream-level `check` mode during initialization and, for each block, parses the trailing block checksum or hash. However, for supported non-`none` modes (`crc32`, `crc64`, `sha256`), the implementation discards the declared value without validating it against the bytes actually produced by decompression. As a result, tampered block contents are accepted and returned to callers if the rest of the XZ structure remains valid.

## Provenance
- Verified from the provided finding and reproducer
- Reproduced against the standard library XZ decompressor implementation
- Reference: https://swival.dev

## Preconditions
- Attacker controls XZ block bytes and the declared checksum field
- The XZ stream advertises a supported block check mode other than `none`
- Remaining container structure, sizes, and index/footer checks stay valid

## Proof
The reproduction used the committed fixture `lib/std/compress/xz/testdata/good-1-check-crc32.xz`.

A single payload byte in the block was modified while leaving the original block CRC32 unchanged:
- block payload starts at byte 24
- the `H` in `Hello` is at byte 27
- block CRC32 is at bytes 44..47
- byte 27 was changed from `0x48` to `0x4a`, producing `Jello\nWorld!\n`
- the stale block CRC32 `43 a3 a2 15` was left intact

A `zig test --zig-lib-dir lib` harness using `std.compress.xz.Decompress` still decompressed successfully and returned the modified plaintext instead of failing with `error.WrongChecksum`.

Source inspection matches the observed behavior:
- initialization stores the stream `check`
- block reads always consume the declared checksum after `readBlock`
- for `.crc32`, `.crc64`, and `.sha256`, the declared checksum/hash is parsed but not compared
- block counting proceeds as if integrity verification succeeded

## Why This Is A Real Bug
XZ block checks are an integrity mechanism for block payloads. Accepting altered block output while ignoring the advertised and parsed block checksum defeats that mechanism and allows silent data corruption or malicious content substitution. This is directly security-relevant because the API returns attacker-controlled modified bytes as trusted decompressed output.

## Fix Requirement
Compute the advertised block checksum or hash over the exact bytes emitted for each block and compare it with the declared trailing value before accepting the block. On mismatch, fail with `error.WrongChecksum` before incrementing block state.

## Patch Rationale
The patch adds real per-block verification for supported check modes by hashing the decompressed bytes produced for each block and validating them against the parsed trailing checksum/hash. This preserves existing parsing behavior, enforces the XZ integrity contract at the point where the block is finalized, and converts silent acceptance of tampered payloads into an explicit checksum failure.

## Residual Risk
None

## Patch
- Patched in `077-block-checksums-are-parsed-but-never-verified.patch`
- The fix updates `lib/std/compress/xz/Decompress.zig` to verify parsed block checksums instead of discarding them