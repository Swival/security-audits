# realpath stub returns input unchanged

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/os/win32/ngx_files.c:456`
- `src/http/ngx_http_variables.c:1716`
- `src/http/ngx_http_variables.c:1731`

## Summary
On Windows, `ngx_realpath()` was a stub that unconditionally returned the caller-provided `path` pointer unchanged and did not write to `resolved`. As a result, code expecting canonical filesystem resolution received the original, possibly relative or non-canonical string instead. This directly broke `$realpath_root`, which propagated an unverified alias rather than a canonical absolute path.

## Provenance
- Verified from local reproduction and patch preparation
- Scanner reference: https://swival.dev

## Preconditions
- Windows build calls `ngx_realpath` for path normalization
- A caller depends on canonicalized output, including `$realpath_root`

## Proof
`ngx_realpath()` in `src/os/win32/ngx_files.c:456` immediately returned `path` without performing any filesystem resolution or canonicalization. The body was unconditional, so every invocation failed to normalize input.

The reproduced propagation path for the user-visible case was:
- configured or computed root
- `ngx_http_variable_realpath_root()`
- `ngx_realpath()` stub
- variable value copy at `src/http/ngx_http_variables.c:1716`
- fallback handling at `src/http/ngx_http_variables.c:1731`

Observed practical behavior:
- `C:/site/../current` remained unchanged
- redundant separators and dot segments remained unchanged
- junction/symlink aliases were not canonicalized
- nonexistent paths did not fail at the realpath step

## Why This Is A Real Bug
The function name, call sites, and Unix behavior all imply canonical path resolution semantics. Returning the input bytes unchanged violates that contract. On Windows, this causes `$realpath_root` and any downstream config, logging, rewrite, or upstream parameter logic using it to operate on a non-canonical alias instead of a verified filesystem path. The bug is unconditional and directly reachable.

## Fix Requirement
Implement Windows path canonicalization in `ngx_realpath()` and write the normalized absolute result into `resolved`, failing when resolution cannot be completed.

## Patch Rationale
The patch replaces the stub with real Windows path handling so `ngx_realpath()` produces canonical output consistent with its intended contract. This restores meaningful behavior for `$realpath_root` and aligns Windows handling with caller expectations instead of silently returning unchecked input.

## Residual Risk
None

## Patch
- Patch file: `018-realpath-stub-returns-input-unchanged.patch`
- The patch implements Windows canonicalization in `src/os/win32/ngx_files.c` so `ngx_realpath()` populates `resolved` with a normalized absolute path rather than returning the original input unchanged.