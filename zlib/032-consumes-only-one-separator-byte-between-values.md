# Consumes only one separator byte between values

## Classification
- Type: data integrity bug
- Severity: low
- Confidence: certain

## Affected Locations
- `contrib/puff/bin-writer.c:20`

## Summary
- `bin-writer` consumes exactly one separator byte after each parsed hex pair.
- When input contains multiple delimiter bytes between values, the next iteration reads a delimiter as part of the next pair and corrupts output.
- The patch skips separators before each hex pair and validates that both consumed characters are hexadecimal digits.

## Provenance
- Verified from the provided reproducer and source inspection.
- External reference: https://swival.dev

## Preconditions
- `stdin` contains hex pairs separated by more than one delimiter byte.

## Proof
- In `main`, the original loop reads two bytes into `hexStr`, converts them with `strtol(..., 16)`, writes one byte, then calls `getchar()` once to discard a separator.
- For `41  42`, the first iteration emits `0x41` and consumes only the first space. The second space remains pending.
- On the next iteration, `hexStr` becomes `" 4"`, so `strtol(" 4", 16)` yields `0x04` instead of `0x42`, producing `4104` rather than `4142`.
- The same desynchronization occurs with repeated non-whitespace delimiters, e.g. `41,,42` causes the next pair to begin with `,` and emits `0x00`.
- Reported reproductions:
  - `printf '41 42' | ... | xxd -p` -> `4142`
  - `printf '41  42' | ... | xxd -p` -> `4104`
  - `printf '41\n\n42' | ... | xxd -p` -> `4104`
  - `printf '41,,42' | ... | xxd -p` -> `4100`

## Why This Is A Real Bug
- The program’s purpose is to convert a hex-encoded byte stream into binary output.
- Accepting separator-delimited input but skipping only one delimiter byte causes deterministic output corruption for valid-looking inputs with repeated separators.
- This is reachable from standard input alone and affects all subsequent bytes after the first repeated delimiter.

## Fix Requirement
- Skip delimiters in a loop before reading each hex pair.
- Reject input unless both consumed characters are hexadecimal digits.

## Patch Rationale
- Skipping separators before parsing prevents delimiter bytes from being misinterpreted as hex input, regardless of how many consecutive separators appear.
- Explicit hex-digit validation prevents `strtol` from silently accepting malformed pairs such as `" 4"` or `",4"` and emitting unintended bytes.
- This directly addresses the reproduced corruption mechanism without changing the intended conversion behavior for well-formed input.

## Residual Risk
- None

## Patch
- Patch file: `032-consumes-only-one-separator-byte-between-values.patch`
- The patch updates `contrib/puff/bin-writer.c` to:
  - consume separator bytes in a loop before each byte parse
  - require two actual hex-digit characters for each output byte
  - avoid silent desynchronization on repeated delimiters