# Writes byte for incomplete trailing hex pair

## Classification
- Type: data integrity bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:15`

## Summary
- `bin-writer` consumes hex input from `stdin` in two-character chunks, but it does not verify that the second nibble exists before converting and writing a byte.
- If input ends after a single trailing hex nibble, the code still calls `strtol()` and `fwrite()`, causing one byte to be emitted from incomplete input and corrupting the output stream.

## Provenance
- Verified by reproduction against the reported code path and patched accordingly.
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- `stdin` ends after a single trailing hex nibble.

## Proof
- In `contrib/puff/bin-writer.c:15`, the loop reads the first hex nibble from `stdin`.
- The next `getchar()` result is assigned into `hexStr[1]` without checking for `EOF`.
- When that second read returns `EOF`, the code still null-terminates `hexStr` and passes it to `strtol(..., 16)`.
- `strtol()` accepts the leading nibble as a valid hexadecimal value and stops at the non-hex trailing byte.
- The resulting partial value is then written with `fwrite()`, so odd-length input produces an unintended output byte.
- Reproducer: `printf 'A' | bin-writer | od -An -tx1` outputs `0a`, proving that incomplete input emits a byte.

## Why This Is A Real Bug
- The program promises byte-oriented decoding from hex pairs, so emitting a byte from a lone trailing nibble violates input-to-output integrity.
- The behavior is directly reachable from untrusted `stdin` input with no special environment or race needed.
- The reproduced output demonstrates silent corruption rather than a harmless parse failure.

## Fix Requirement
- Check the second `getchar()` result for `EOF` before calling `strtol()` or `fwrite()`.
- On missing trailing nibble, stop with an error path rather than converting partial input.

## Patch Rationale
- The patch adds an explicit `EOF` check after reading the second nibble.
- This prevents partial buffers from reaching `strtol()` and guarantees that only complete hex pairs are written as bytes.
- The change is minimal, local to the faulty read/convert path, and preserves normal behavior for valid even-length input.

## Residual Risk
- None

## Patch
- Patch file: `030-writes-byte-for-incomplete-trailing-hex-pair.patch`
- Patched file: `contrib/puff/bin-writer.c`