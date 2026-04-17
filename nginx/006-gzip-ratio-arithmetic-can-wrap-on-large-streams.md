# gzip_ratio arithmetic can wrap on large streams

## Classification
- Type: logic error
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_gzip_filter_module.c:716`

## Summary
`$gzip_ratio` derives its printable value from `ctx->zin` and `ctx->zout` after gzip completes. The existing implementation multiplies `ctx->zin` by `100` and `1000` before dividing by `ctx->zout`, so on 32-bit builds the intermediate `size_t` arithmetic can wrap for large-but-practical response sizes. This produces incorrect ratio strings even though compression itself succeeds.

## Provenance
- Verified finding reproduced from the provided report
- Reproduction and patch analysis performed against the local source tree
- Reference: https://swival.dev

## Preconditions
- gzip processes a very large response stream
- `$gzip_ratio` is evaluated, such as during access logging

## Proof
`ngx_http_gzip_filter_deflate_end()` stores `ctx->zstream.total_in` into `ctx->zin`, and `ngx_http_gzip_ratio_variable()` later formats `$gzip_ratio` from `ctx->zin` and `ctx->zout`. The vulnerable code path performs scaled multiplication before division, equivalent to:
```c
ctx->zin * 100 / ctx->zout
ctx->zin * 1000 / ctx->zout
```
On 32-bit targets, these intermediates wrap in `size_t` for sufficiently large `ctx->zin`.

The path is reachable in normal operation:
- `$gzip_ratio` is registered as an HTTP variable at `src/http/modules/ngx_http_gzip_filter_module.c:1009`
- nginx evaluates log variables during the log phase after body filtering completes, including request variables used by the log module at `src/http/ngx_http_request.c:3981`, `src/http/ngx_http_request.c:3993`, and `src/http/modules/ngx_http_log_module.c:279`

Concrete reproduced example on 32-bit nginx:
- `zin = 5,000,000`
- `zout = 1,000,000`
- Correct ratio: `5.00`
- Current wrapped arithmetic can emit `5.01`

## Why This Is A Real Bug
This is not theoretical dead code. `$gzip_ratio` is a standard exported variable and is commonly consumed in logging after gzip finalization, exactly when `ctx->zin` and `ctx->zout` are populated. nginx still supports 32-bit targets in-tree, including `src/core/ngx_config.h:78` and `src/os/win32/ngx_win32_config.h:226`, so the overflow is reachable on supported builds with realistic response sizes. The impact is limited to incorrect observability data, but that is still a correctness bug in exposed server behavior.

## Fix Requirement
Compute the integral and fractional ratio digits without overflow-prone pre-scaling. The fix must avoid multiplying `ctx->zin` by `100` or `1000` before division, while preserving existing output formatting.

## Patch Rationale
The patch replaces overflow-prone scaled multiplication with divide-first arithmetic that derives the integer quotient and successive decimal digits from the quotient and remainder. This preserves the intended `$gzip_ratio` formatting while eliminating wraparound on large 32-bit streams.

## Residual Risk
None

## Patch
- Patched in `006-gzip-ratio-arithmetic-can-wrap-on-large-streams.patch`
- Updated `src/http/modules/ngx_http_gzip_filter_module.c` to format `$gzip_ratio` using overflow-safe quotient/remainder math instead of `ctx->zin * 100` / `ctx->zin * 1000` intermediate products