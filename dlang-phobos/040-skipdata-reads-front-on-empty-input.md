# skipData reads front on empty input

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `std/format/internal/read.d:28`

## Summary
- `skipData` dereferences or consumes the front of `input` without first proving the range is non-empty.
- The `%c` case unconditionally calls `input.popFront()`.
- The `%d` case evaluates `input.front` for sign handling before any emptiness guard, then falls through to `%u`.
- Empty input can reach this helper through skipped fields, causing a runtime assertion failure instead of clean parse handling.

## Provenance
- Verified by runtime reproduction against the checked-out source tree.
- Scanner source: https://swival.dev

## Preconditions
- Empty input reaches `skipData` with `%c` or `%d`.

## Proof
- `skipData` is called on caller-provided `input` and branches on `spec.spec`.
- For `%c`, it executes `input.popFront()` with no prior `input.empty` check.
- For `%d`, it reads `input.front` to test for `+` or `-` with no prior emptiness check, then proceeds into unsigned-digit skipping logic.
- `readUpToNextSpec` can advance to a skipped conversion without consuming any input, so empty input remains possible at the callsite.
- Runtime reproduction confirms reachability:
  - `formattedRead("", "%*c%s", value)` aborts with `Attempting to popFront() past the end of an array of char`.
  - `formattedRead("", "%*d", value)` aborts with `Attempting to fetch the front of an empty array of char`.
- Both failures originate from `std.format.internal.read.skipData`.

## Why This Is A Real Bug
- The crash is directly reachable from public formatting APIs using malformed or exhausted input and skipped fields.
- This is not a benign edge case: the function violates range preconditions internally and terminates the process via assertion failure.
- Existing downstream emptiness checks do not protect this path because `skipData` is reached before those guards execute.

## Fix Requirement
- Guard `%c` and `%d` with `!input.empty` before any `front` or `popFront` access.

## Patch Rationale
- The patch adds emptiness checks at the point of use inside `skipData`.
- This preserves existing behavior for non-empty input while converting the empty-input case from an internal invariant violation into normal no-progress handling.
- Fixing locally is appropriate because the helper itself performs the unsafe operations and cannot rely on all callers to establish the precondition.

## Residual Risk
- None

## Patch
- Patch file: `040-skipdata-reads-front-on-empty-input.patch`
- Change: add `!input.empty` guards before `%c` `popFront()` and `%d` sign inspection in `std/format/internal/read.d`.