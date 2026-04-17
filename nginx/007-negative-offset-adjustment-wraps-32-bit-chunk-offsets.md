# 32-bit stco offset adjustment wraps on rewrite

## Classification
- Type: data integrity bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_mp4_module.c:3634`
- `src/http/modules/ngx_http_mp4_module.c:3665`
- `src/http/modules/ngx_http_mp4_module.c:3725`

## Summary
`ngx_http_mp4_process()` can retain `stco` entries without proving that every rewritten 32-bit chunk offset remains in range after applying the computed adjustment. `ngx_http_mp4_adjust_stco_atom()` then rewrites each retained entry with unchecked 32-bit arithmetic, allowing wraparound and emitting corrupted chunk locations in the served MP4.

## Provenance
- Verified from the supplied reproducer and sink analysis in `src/http/modules/ngx_http_mp4_module.c`
- Reference: https://swival.dev

## Preconditions
- Valid MP4 using 32-bit `stco` chunk offsets
- MP4 rewrite path is exercised
- A retained chunk offset plus the applied adjustment exceeds `UINT32_MAX`

## Proof
- `ngx_http_mp4_process()` computes and propagates the chunk offset adjustment, but the retention checks at `src/http/modules/ngx_http_mp4_module.c:3634` and `src/http/modules/ngx_http_mp4_module.c:3665` do not establish that all surviving `stco` entries can absorb the adjustment without overflowing 32 bits.
- `ngx_http_mp4_adjust_stco_atom()` rewrites each retained entry by loading a `uint32_t offset` and applying `offset += adjustment` at `src/http/modules/ngx_http_mp4_module.c:3725`.
- For a valid `stco` file with later retained offsets near `0xffffffff`, a positive adjustment causes modulo-`2^32` wrap. The output MP4 then advertises a low, incorrect chunk offset, redirecting reads to the wrong bytes in the served `mdat` slice.
- This was reproduced with a valid large `stco` MP4 where all original offsets remain below 4 GiB, `moov` follows `mdat`, and `?start=0` triggers rewrite with a later retained entry exceeding `UINT32_MAX - adjustment`.

## Why This Is A Real Bug
The resulting file is syntactically rewritten but semantically corrupted: chunk tables point at the wrong media data. This is a direct integrity failure in generated output, is reachable with valid input, and does not rely on malformed atoms or undefined behavior outside the module's own unchecked arithmetic.

## Fix Requirement
Before rewriting any retained `stco` entry, perform checked wider arithmetic and reject results outside `[0, UINT32_MAX]`; alternatively, reject any track whose retained 32-bit chunk offsets cannot safely absorb the computed adjustment.

## Patch Rationale
The patch hardens the `stco` rewrite sink by validating adjusted offsets before encoding them back into 32-bit entries. This prevents modulo wraparound and fails the rewrite instead of emitting corrupted chunk tables.

## Residual Risk
None

## Patch
- Patch file: `007-negative-offset-adjustment-wraps-32-bit-chunk-offsets.patch`
- The patch adds explicit bounds checks around `stco` offset adjustment in `src/http/modules/ngx_http_mp4_module.c`, ensuring rewritten 32-bit chunk offsets cannot wrap during MP4 response generation.