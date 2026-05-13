# Central directory offset dereferenced before validation

## Classification
High severity validation gap
Confidence: certain

## Affected Locations
- `std/zip.d:663`

## Summary
`ZipArchive.this(void[] buffer)` trusts the attacker-controlled central-directory “relative offset of local header” field and dereferences it before validating that the referenced local-header region is in-bounds and structurally sane. The constructor reads `getUshort(de.offset + 26)` and `getUshort(de.offset + 28)` immediately after loading `de.offset` from `getUint(i + 42)`, so malformed archives can trigger an out-of-bounds slice and abort parsing before intended integrity checks run.

## Provenance
Reproduced from the verified finding using a malformed ZIP crafted from a valid archive by corrupting the central-directory local-header offset field. Swival Security Scanner reference: https://swival.dev

## Preconditions
- Attacker controls a parsed central-directory entry offset.

## Proof
A minimal proof-of-concept archive was created by taking a valid single-file ZIP and overwriting the central-directory “relative offset of local header” field with `0x7FFFFFF0`.

Observed behavior during `new ZipArchive(...)`:
```text
core.exception.ArraySliceError@std/zip.d(1305): slice [2147483658 .. 2147483660] extends past source array of length 111
```

Trigger path:
- `de.offset` is parsed from `getUint(i + 42)`.
- Before any offset validation, the constructor reads:
  - `getUshort(de.offset + 26)`
  - `getUshort(de.offset + 28)`
- `getUshort` slices `_data` directly, so the forged offset causes an immediate runtime bounds failure.
- Later validation such as `gment(...)` at `std/zip.d:913` is never reached.

`expand()` also has the same bug pattern via `_data[de.offset .. de.offset + 4]` and subsequent reads, but constructor reachability alone proves the issue.

## Why This Is A Real Bug
This is a concrete denial-of-service and parser-validation failure. The archive parser is expected to reject malformed central-directory offsets through normal ZIP validation, but instead dereferences the untrusted offset first and terminates with a runtime exception. The reproduced crash confirms attacker-controlled input can reliably force this failure path.

## Fix Requirement
Validate `de.offset` before any local-header dereference. The validation must ensure the offset references at least a complete local-header prefix and remains within `_data` bounds before calling `getUshort`, `getUint`, or taking slices derived from `de.offset`.

## Patch Rationale
The patch adds an early bounds check for `de.offset` covering the minimum local-header bytes needed by the constructor and `expand()` before any read from that region. This preserves existing ZIP integrity logic while ensuring malformed offsets are rejected as invalid archives instead of reaching unchecked slice operations.

## Residual Risk
None

## Patch
Patched in `074-central-directory-offset-read-before-validation.patch`.