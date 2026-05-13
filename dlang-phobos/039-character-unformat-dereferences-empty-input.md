# Character unformat dereferences empty input

## Classification
- Type: invariant violation
- Severity: high
- Confidence: certain

## Affected Locations
- `std/format/internal/read.d:131`
- `std/format/read.d:838`

## Summary
`unformatValueImpl` for character targets handles `%s` and `%c` by reading `input.front` and then `input.popFront()` without first verifying that the input range is non-empty. This violates the input-range precondition on empty input and fails before format-aware error handling can run. The issue is reachable through the public `unformatValue` API.

## Provenance
- Verified from source and reproduction on the target codebase
- Swival Security Scanner: https://swival.dev

## Preconditions
- An empty character input range is passed to `unformatValue` for a character type
- The active format specifier is `%s` or `%c`

## Proof
- `std/format/internal/read.d:131` enters the `isSomeChar!T` branch for `%s` and `%c` and immediately evaluates `to!T(input.front)` followed by `input.popFront()`.
- That branch performs no `input.empty` check before dereferencing `front`.
- `std/format/read.d:838` exposes this behavior via the public `unformatValue` wrapper.
- Reproduction confirmed that `unformatValue!char(empty, singleSpec("%c"))` on `empty = ""` fails immediately on the empty-range dereference path.
- `formattedRead` does not reproduce this exact path because `std/format/read.d:269` returns early on empty input, so the confirmed bug is specifically on direct `unformatValue` use.

## Why This Is A Real Bug
Accessing `front` on an empty input range is invalid by the range contract. Here that invalid access occurs before any controlled format failure is raised, so callers can get an assertion, abort, or equivalent low-level failure instead of a `FormatException`. This is observable, source-backed, and reachable through a public API.

## Fix Requirement
Add an `enforceFmt(!input.empty, ...)` guard before any `%s` or `%c` character read that dereferences `input.front`, so empty input is rejected through normal format error handling.

## Patch Rationale
The patch inserts the required emptiness check immediately before the `%s`/`%c` character read in `std/format/internal/read.d`, preserving existing parsing behavior for valid input while converting the invalid empty-input path into a controlled formatting error.

## Residual Risk
None

## Patch
- Patch file: `039-character-unformat-dereferences-empty-input.patch`
- Change: guard `%s`/`%c` character unformat in `std/format/internal/read.d` with `enforceFmt(!input.empty, ...)` before reading `input.front` and calling `input.popFront()`