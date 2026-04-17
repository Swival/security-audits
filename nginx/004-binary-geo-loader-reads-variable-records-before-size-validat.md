# Binary geo loader bounds-checks variable and range records before dereference

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_geo_module.c:1015`

## Summary
- `ngx_http_geo_include_binary_base()` trusted attacker-controlled `.bin` structure layout before confirming the file was large enough for the header, variable-value records, and range records.
- The loader set pointers into `base` and evaluated sentinel fields like `vv->data` and `range->value` before checking those structs were still within `base + size`.
- A malformed geo binary could therefore trigger out-of-bounds reads during configuration loading, before CRC validation rejected the file.

## Provenance
- Verified from the supplied reproducer and source inspection in `src/http/modules/ngx_http_geo_module.c`
- Reproduced against the vulnerable parsing path described in the finding
- Scanner reference: https://swival.dev

## Preconditions
- Attacker controls a loaded geo `.bin` file

## Proof
- The loader casts the mapped file to `ngx_http_geo_header_t *` and then derives `vv` from the raw buffer before validating minimum file size.
- With a 16-byte file, `vv` lands exactly one element past the allocation and the first loop condition dereferences `vv->data` out of bounds.
- The same pattern exists in subsequent range parsing, where sentinel-driven iteration reads `range->value` before ensuring the current record fits inside the file.
- Reproducer conditions are practical: a `ranges` geo block, matching `.bin` and source names, a non-stale `.bin`, and a crafted 16-byte header-valid file are sufficient to reach the fault before CRC rejection.

## Why This Is A Real Bug
- The bug is reachable in normal configuration parsing, not behind debug-only code or impossible state.
- The out-of-bounds access happens on attacker-controlled input and occurs before integrity checks, so malformed binaries can crash the parser or cause undefined behavior during config load.
- The one-past-end read is directly implied by structure size and pointer arithmetic, and was confirmed by reproduction.

## Fix Requirement
- Enforce a minimum binary size before any struct cast or field dereference.
- Validate each variable-value and range record boundary before reading sentinel fields or advancing to the next record.
- Reject malformed binaries immediately when a record would extend past `base + size`.

## Patch Rationale
- The patch adds explicit size guards ahead of the initial header access and before each record dereference in the variable-value and range walks.
- This preserves the existing file format and sentinel-based parsing logic while ensuring every step stays within the mapped buffer.
- The change fails closed on malformed input and blocks the reproduced one-past-end read as well as the analogous later range walk issue.

## Residual Risk
- None

## Patch
- Patched in `004-binary-geo-loader-reads-variable-records-before-size-validat.patch`
- The patch hardens `src/http/modules/ngx_http_geo_module.c` by validating minimum file size and per-record bounds before dereferencing `ngx_http_variable_value_t` and range entries.