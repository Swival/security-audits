# Raw `%r` read indexes past end of narrow string input

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/format/internal/read.d:268`
- `std/format/internal/read.d:272`
- `std/format/internal/read.d:273`

## Summary
`rawRead!T` handles `%r` parsing from narrow strings by iterating `0 .. T.sizeof` and consuming `input[0]` / `input = input[1 .. $]` on each iteration without first verifying that at least `T.sizeof` bytes remain. When the input string is shorter than `T.sizeof`, this path throws `ArrayIndexError` instead of failing formatting normally.

## Provenance
- Verified from the supplied reproducer and patch context
- Scanner source: https://swival.dev

## Preconditions
- `%r` unformats from a narrow string shorter than `T.sizeof`

## Proof
- `unformatValueImpl(..., spec)` routes `%r` handling into `rawRead!T(input)` for narrow string / byte-range inputs.
- In the string-specific branch of `rawRead`, the code loops `0 .. T.sizeof` and reads `input[0]` before slicing one byte off each iteration.
- No guard ensures `input.length >= T.sizeof` before the loop begins.
- Reproducer: `string s = "A"; unformatValue!int(s, singleSpec("%r"))`
- Observed runtime result under `ldc2`: `core.exception.ArrayIndexError: index [0] is out of bounds for array of length 0`

## Why This Is A Real Bug
The `%r` parser is expected to reject insufficient input through the formatting error path. Instead, short malformed input triggers an uncaught runtime bounds exception. That is externally triggerable denial-of-service behavior for callers that rely on `unformat` to fail cleanly on invalid input.

## Fix Requirement
Before consuming bytes in the narrow-string branch of `rawRead`, require at least `T.sizeof` bytes to remain; otherwise raise the normal formatting failure.

## Patch Rationale
The patch in `038-raw-read-indexes-past-end-of-string-input.patch` adds the missing precondition check ahead of the byte-consumption loop in `std/format/internal/read.d`. This preserves existing `%r` semantics for valid inputs while converting undersized inputs from a runtime bounds trap into an expected formatting failure.

## Residual Risk
None

## Patch
- Patch file: `038-raw-read-indexes-past-end-of-string-input.patch`
- Target: `std/format/internal/read.d`
- Change: add a length check before the narrow-string `%r` byte loop so short input fails through the formatter instead of indexing past the end of the string