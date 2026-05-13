# Timezone name escapes database directory

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `std/datetime/timezone.d:1275`
- `std/datetime/timezone.d:2111`

## Summary
`PosixTimeZone.getTimeZone` accepts attacker-controlled `name`, strips it, and uses it to build a filesystem path under the timezone database directory without rejecting absolute paths or parent-directory traversal. A crafted value such as `../../other.tzif` or `/tmp/evil.tzif` escapes `tzDatabaseDir`, reaches `File(file)`, and causes an external file to be opened and parsed.

## Provenance
- Reproduced from the verified finding and patch workflow.
- Scanner reference: https://swival.dev

## Preconditions
- Attacker controls `name` passed to `PosixTimeZone.getTimeZone`.

## Proof
- At `std/datetime/timezone.d:1275`, `name` is stripped and passed into path construction with `tzDatabaseDir`.
- No validation rejects absolute paths or `..` path segments before normalization.
- The resulting path is later opened with `File(file)` at `std/datetime/timezone.d:2111`.
- Reproduction confirmed that inputs like `../../some/other/file` and absolute paths can escape `tzDatabaseDir` and reach the open call.
- If the target is a valid TZif file, it is parsed from outside the database directory; otherwise the code still opens the external file before failing parser checks.

## Why This Is A Real Bug
This is a real directory traversal in a security-sensitive file-loading path. The bug allows attacker influence over which regular file the library opens, outside the configured timezone database root. Even though non-TZif files are typically rejected after opening, the unauthorized path reachability and acceptance of attacker-chosen external TZif files are sufficient to establish impact.

## Fix Requirement
Reject timezone names that are absolute paths or contain any `..` path segments before constructing the final filesystem path.

## Patch Rationale
The patch enforces input validation on `name` prior to `chainPath(...)`, blocking traversal primitives at the source. This preserves expected timezone identifier handling while preventing escape from `tzDatabaseDir` and preventing `File(file)` from reaching attacker-selected external paths.

## Residual Risk
None

## Patch
- Patch file: `041-timezone-name-escapes-database-directory.patch`
- Implemented change: validate `name` in `std/datetime/timezone.d` to reject absolute paths and parent-directory traversal before building the timezone database path.