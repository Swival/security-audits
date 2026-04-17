# Slice range construction can overflow

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_slice_filter_module.c:164`
- `src/http/modules/ngx_http_slice_filter_module.c:201`
- `src/http/modules/ngx_http_slice_filter_module.c:206`
- `src/http/modules/ngx_http_slice_filter_module.c:212`
- `src/http/modules/ngx_http_slice_filter_module.c:278`

## Summary
The slice filter constructs byte ranges with unchecked signed `off_t` arithmetic derived from client-controlled range state and configured slice size. When `ctx->start` is near `NGX_MAX_OFF_T_VALUE`, computing `ctx->start + (off_t) slcf->size - 1` can overflow, causing undefined behavior and malformed outbound `Range` headers.

## Provenance
- Verified from the supplied reproducer and code inspection in `src/http/modules/ngx_http_slice_filter_module.c`
- Reproduction source: Swival Security Scanner, `https://swival.dev`

## Preconditions
- `slice` is enabled for the location
- `slcf->size` is positive
- `ctx->start` is attacker-reachable near `NGX_MAX_OFF_T_VALUE` via request range handling or later slice state updates

## Proof
The reproduced case uses a large request range such that the slice floor step yields `ctx->start = 9223372036854775805`. With `slcf->size = 5`, the module formats the slice range end as `ctx->start + (off_t) slcf->size - 1 = 9223372036854775809`, which exceeds `NGX_MAX_OFF_T_VALUE` (`9223372036854775807`).

At `src/http/modules/ngx_http_slice_filter_module.c:212` and `src/http/modules/ngx_http_slice_filter_module.c:278`, this unchecked expression is used directly when formatting `bytes=%O-%O`. Related unchecked additions that can participate in the same invalid state transition are present at `src/http/modules/ngx_http_slice_filter_module.c:164`, `src/http/modules/ngx_http_slice_filter_module.c:201`, and `src/http/modules/ngx_http_slice_filter_module.c:206`.

Because `off_t` is signed, overflowing this addition is undefined behavior in C. In practice this can wrap and emit an invalid upstream `Range` header.

## Why This Is A Real Bug
The triggering inputs are reachable from normal request processing: `ctx->start` comes from parsed request or upstream range values, and `slcf->size` comes from configuration. No guard enforces that the computed range end remains within `off_t` bounds before formatting or state advancement. The result is not a harmless theoretical overflow; it breaks the module's core invariant that generated slice ranges are valid and bounded, and it can induce request failures or malformed upstream behavior for a single client request.

## Fix Requirement
Before any slice range end is computed or slice state is advanced, enforce an overflow guard equivalent to rejecting or clamping when `ctx->start > NGX_MAX_OFF_T_VALUE - (off_t) slcf->size + 1`. Apply the check consistently to every code path that derives the end offset or increments `ctx->start` from slice size.

## Patch Rationale
The patch in `008-slice-range-construction-can-overflow.patch` should centralize or consistently apply pre-addition bounds checks so all affected constructions fail safely before signed overflow occurs. This preserves the slice invariant, avoids undefined behavior, and prevents malformed outbound `Range` headers while keeping normal slice generation unchanged for in-range values.

## Residual Risk
None

## Patch
- Add explicit `off_t` overflow guards in `src/http/modules/ngx_http_slice_filter_module.c` before computing slice end offsets or advancing `ctx->start`
- Reject the request path safely when the next slice computation would exceed `NGX_MAX_OFF_T_VALUE`
- Cover both direct `bytes=%O-%O` formatting sites and the related unchecked additions participating in the same state flow
- Record the change in `008-slice-range-construction-can-overflow.patch`