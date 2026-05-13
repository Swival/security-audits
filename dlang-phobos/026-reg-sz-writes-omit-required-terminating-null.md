# REG_SZ writes omit required terminating null

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `std/windows/registry.d:853`

## Summary
`Key.setValue(string, string, bool)` writes `REG_SZ` and `REG_EXPAND_SZ` data with `cbData` computed from `lstrlenW(pszTmp) * wchar.sizeof`, which excludes the required terminating UTF-16 NUL. That size is passed unchanged to `RegSetValueExW`, producing malformed registry string values.

## Provenance
- Verified from source and reproducer evidence supplied for `std/windows/registry.d`
- External API behavior aligns with Windows registry requirements documented and observed in practice
- Reference: https://swival.dev

## Preconditions
- Caller stores a string value via `Key.setValue` on Windows

## Proof
- `Key.setValue(string, string, bool)` converts the D string with `tempCStringW()`
- It computes `len` from `lstrlenW(pszTmp) * wchar.sizeof`
- It passes that byte count to `regSetValue`, which forwards `cbData` unchanged to `RegSetValueExW`
- For `REG_SZ` and `REG_EXPAND_SZ`, `RegSetValueExW` expects the byte count to include the trailing UTF-16 NUL
- Local readback code later assumes that invariant and asserts the final `wchar` is `'\0'` in `std/windows/registry.d:554` and `std/windows/registry.d:555`
- A value written through this path can therefore be malformed on disk and trigger assertion failure on readback in checked builds

## Why This Is A Real Bug
The bug is directly reachable through a normal public API with no unusual setup. The write path violates the Windows API contract for registry string types, and the same module's read path depends on the missing terminator being present. This creates both persistent malformed state and a concrete failure mode during subsequent reads.

## Fix Requirement
Include the terminating UTF-16 NUL in `cbData` for `REG_SZ` and `REG_EXPAND_SZ` writes before calling `RegSetValueExW`.

## Patch Rationale
The patch adjusts the byte-count calculation for string registry writes so the serialized size matches Windows expectations for NUL-terminated UTF-16 registry strings. This is the minimal targeted fix: it preserves existing encoding and call flow while correcting the API contract violation that caused malformed values.

## Residual Risk
None

## Patch
- `026-reg-sz-writes-omit-required-terminating-null.patch` updates `std/windows/registry.d` so `REG_SZ` and `REG_EXPAND_SZ` writes include the trailing UTF-16 NUL in `cbData` passed to `RegSetValueExW`