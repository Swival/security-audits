# Binary geo loader trusts unbounded range sentinels

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_geo_module.c:1033`
- `src/http/modules/ngx_http_geo_module.c:1548`

## Summary
The binary geo loader parses serialized value and range arrays by scanning for zero sentinels without enforcing `base + size` bounds on each dereference. A malformed `.bin` file that omits terminators before EOF causes out-of-bounds reads during config load, crashing `nginx` on `nginx -t`, startup, or reload.

## Provenance
- Verified from the supplied finding and reproducer details
- Reproduced against the affected parsing paths in `src/http/modules/ngx_http_geo_module.c`
- Reference: https://swival.dev

## Preconditions
- Worker loads an attacker-controlled `.bin` geo range base

## Proof
`include` in range mode reaches `ngx_http_geo_include_binary_base()`, which reads the binary file into `base` and then walks embedded tables.

At `src/http/modules/ngx_http_geo_module.c:1033`, the value table scan uses a sentinel loop over serialized `ngx_http_variable_value_t` entries:
- `while (vv->data)` advances through file-backed records
- no `base + size` bound is enforced before dereferencing `vv->data` or consuming `vv->len`
- a crafted nonzero `data` with oversized `len` drives `ngx_crc32_update()` beyond the mapped buffer

The same bug class exists in range parsing at `src/http/modules/ngx_http_geo_module.c:1548`:
- the outer walk checks the start of each range block against `base + size`
- the inner `while (range->value)` loop does not ensure the terminating entry is still inside the mapped file
- if a range array begins in-bounds but lacks its null terminator before EOF, parsing reads past the buffer

The reproducer confirmed both conditions:
- a malformed binary file already triggers the parser issue
- a minimal harness mirroring the `vv` loop on a page-protected buffer crashes with a synchronous `Bus error` when the crafted record forces the CRC walk past the mapping

## Why This Is A Real Bug
This is a concrete memory-safety failure in reachable config-load code, not a theoretical parser concern. The loader fully trusts untrusted in-file sentinels to terminate variable-length serialized sections. When those sentinels are missing or delayed beyond EOF, the parser dereferences and processes file-controlled memory outside the allocated buffer. Because this occurs during configuration validation and reload paths, a malicious geo binary base can reliably cause denial of service.

## Fix Requirement
Reject truncated or unterminated binary geo files by bounding both sentinel-driven scans against `base + size` before every dereference and before any length-based access.

## Patch Rationale
The patch adds explicit end-of-buffer checks to both serialized-table walks in `ngx_http_geo_include_binary_base()`:
- the value-table loop now verifies each `ngx_http_variable_value_t` entry is fully inside the loaded file before reading fields or hashing payload
- the per-block range loop now requires each `ngx_http_geo_range_t` entry, including the terminating sentinel, to remain within `base + size`
- malformed files are rejected early instead of being parsed speculatively

This matches the root cause established by reproduction: insufficient bounds validation of serialized sections.

## Residual Risk
None

## Patch
- Patch file: `005-binary-geo-loader-trusts-unbounded-range-sentinels.patch`
- Patched file: `src/http/modules/ngx_http_geo_module.c`