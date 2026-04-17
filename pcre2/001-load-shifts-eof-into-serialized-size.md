# `#load` short-file EOF corrupts serialized size

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/pcre2test_inc.h:974`

## Summary
`#load` builds `serial_size` from four `fgetc()` calls without checking for `EOF`. On files shorter than four bytes, `fgetc()` returns `-1`, and those values are shifted/ORed into the size field. The corrupted `serial_size` then flows into `malloc(serial_size)` and `fread(serial, 1, serial_size, f)`, producing a forced allocation-failure path and aborting the run.

## Provenance
- Verified from the provided reproducer and source inspection in `src/pcre2test_inc.h:974`
- Scanner provenance: https://swival.dev

## Preconditions
- Attacker controls a short file loaded via `#load`.

## Proof
- At `src/pcre2test_inc.h:974`, `#load` reads the serialized-size header via repeated `fgetc()` calls.
- For a file shorter than 4 bytes, at least one `fgetc()` returns `EOF` (`-1`).
- That `EOF` value is shifted/ORed into `serial_size` instead of being rejected.
- Reproducer results show the derived sizes become huge:
  - empty/short case reached `18446744073709551615`
  - 1-byte file `0x12` reached `18446744073709551378`
  - 2-byte file `0x12 0x34` reached `18446744073709499410`
  - 3-byte file `0x12 0x34 0x56` reached `18446744073698423826`
- The corrupted size is then used in `malloc(serial_size)` and `fread(...)`, causing `pcre2test` to abort on allocation failure.
- A valid 4-byte zero header does not trigger this bug and instead proceeds to normal deserialization failure (`magic number missing`), confirming the trigger is specifically short input hitting unchecked `EOF`.

## Why This Is A Real Bug
This is directly reachable from attacker-controlled input and deterministically converts short-file `EOF` markers into a large allocation size. The result is a practical denial-of-service against the tool’s execution path, not a theoretical parsing concern. The behavior is source-grounded, reproduced, and fixed by rejecting `EOF` before mutating `serial_size`.

## Fix Requirement
Abort `#load` if any of the four header-byte reads returns `EOF`, before updating `serial_size`.

## Patch Rationale
The patch adds explicit `EOF` checks for each header-byte read in `#load` and exits the command path on truncation. This preserves intended behavior for valid files, prevents `EOF` sign-extension from contaminating `serial_size`, and blocks the subsequent oversized `malloc`/`fread` path at the earliest safe point.

## Residual Risk
None

## Patch
- `001-load-shifts-eof-into-serialized-size.patch`