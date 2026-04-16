# Consumes Only One Separator Byte Between Values

## Classification
- Type: data integrity bug
- Severity: low
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:20`

## Summary
`contrib/puff/bin-writer.c` reads exactly one separator byte between hex values with a single `getchar()`. When input contains multiple delimiter bytes between values, parsing becomes misaligned and subsequent output bytes are corrupted.

## Provenance
- Verified from the supplied reproducer and source inspection
- Scanner provenance: https://swival.dev

## Preconditions
- `stdin` contains hex byte pairs separated by more than one delimiter byte

## Proof
- `main` reads two bytes into `hexStr`, converts them with `strtol(..., 16)`, writes one output byte, and then discards exactly one separator byte via `getchar()`.
- With `41  42`, the first loop emits `0x41` and consumes only the first space.
- On the next loop, the remaining space is read as `hexStr[0]` and `'4'` as `hexStr[1]`, so `strtol(" 4", 16)` produces `0x04` instead of `0x42`.
- Verified outputs:
  - `printf '41 42' | ... | xxd -p` -> `4142`
  - `printf '41  42' | ... | xxd -p` -> `4104`
  - `printf '41\n\n42' | ... | xxd -p` -> `4104`
  - `printf '41,,42' | ... | xxd -p` -> `4100`

## Why This Is A Real Bug
The parser accepts streamed input from `stdin` and is intended to convert hex byte pairs into raw bytes. Consuming only one delimiter byte makes output depend on delimiter count rather than encoded values. Any extra separator desynchronizes the parser and causes deterministic output corruption on reachable inputs.

## Fix Requirement
Skip separators in a loop before each hex pair and accept a pair only when both characters are hexadecimal digits.

## Patch Rationale
The patch in `032-consumes-only-one-separator-byte-between-values.patch` addresses the root cause by advancing past arbitrary separator runs before reading a value, instead of assuming exactly one delimiter after each parsed byte. It also validates the two hex characters before conversion so separator-prefixed fragments cannot be misparsed into unintended bytes.

## Residual Risk
None

## Patch
- Patch file: `032-consumes-only-one-separator-byte-between-values.patch`
- Target: `contrib/puff/bin-writer.c`