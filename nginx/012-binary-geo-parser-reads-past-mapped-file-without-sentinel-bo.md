# Binary geo parser reads past mapped file without sentinel bounds check

## Classification
- Type: vulnerability
- Severity: high
- Confidence: certain

## Affected Locations
- `src/stream/ngx_stream_geo_module.c:1009`
- `src/stream/ngx_stream_geo_module.c:1463`
- `src/stream/ngx_stream_geo_module.c:1465`
- `src/stream/ngx_stream_geo_module.c:1489`
- `src/stream/ngx_stream_geo_module.c:1552`
- `src/stream/ngx_stream_geo_module.c:1555`
- `src/stream/ngx_stream_geo_module.c:1584`

## Summary
The binary geo base loader trusts a zeroed `ngx_stream_variable_value_t` sentinel to terminate parsing of embedded variable records. When a loaded `.bin` file omits that sentinel or truncates the subsequent tables, the parser dereferences `vv->data`, advances through aligned records, and then reads the `0x10000`-entry ranges table without ensuring the cursor remains within `base + size`. This causes out-of-bounds reads during configuration load before CRC validation runs.

## Provenance
- Verified from the provided finding and reproducer against `src/stream/ngx_stream_geo_module.c`
- Reproduced with a minimal ASan-backed harness that mirrors the parser flow on a truncated header-only buffer
- Scanner origin: https://swival.dev

## Preconditions
- Attacker controls loaded binary geo base file contents

## Proof
- `include` accepts a binary geo base through `ngx_stream_geo_include_binary_base()`.
- The loader sets `vv = (ngx_stream_variable_value_t *) (base + sizeof(header))` and enters `while (vv->data)` at `src/stream/ngx_stream_geo_module.c:1009` without first proving `vv` still points inside the mapped file.
- On malformed input lacking the terminating zeroed `ngx_stream_variable_value_t`, the first dereference of `vv->data` can already be out of bounds, or later aligned advances can move `vv` beyond `base + size`.
- After the loop, the parser does `vv++` and treats the result as the start of a `0x10000`-entry pointer table, then reads from it at `src/stream/ngx_stream_geo_module.c:1463` and `src/stream/ngx_stream_geo_module.c:1465` with no file-size validation.
- CRC verification occurs only later at `src/stream/ngx_stream_geo_module.c:1489`, so malformed short files trigger out-of-bounds access before integrity checks reject them.
- The writer side emits the expected sentinel and tables in `src/stream/ngx_stream_geo_module.c:1552`, `src/stream/ngx_stream_geo_module.c:1555`, and `src/stream/ngx_stream_geo_module.c:1584`, confirming the reader relies on structure that hostile input is free to omit.

## Why This Is A Real Bug
The failing reads happen on attacker-controlled file contents during config processing, before any checksum-based rejection. This is not a benign format error: the parser performs direct memory accesses past the mapped allocation boundary when sentinel or table data is missing. The reproducer demonstrates the first `vv->data` read overruns immediately on a truncated file, and source inspection shows later fixed-size table reads guarantee further out-of-bounds access on short inputs.

## Fix Requirement
Reject malformed binary geo bases unless every `ngx_stream_variable_value_t` record, each aligned step, the terminating sentinel, and the full ranges table are proven to fit within `base + size` before dereference or pointer arithmetic.

## Patch Rationale
The patch adds explicit upper-bound checks around variable-record iteration and around the post-sentinel table handoff. This preserves existing parsing for valid files while turning malformed or truncated binary bases into clean configuration errors before any out-of-bounds read can occur.

## Residual Risk
None

## Patch
- `012-binary-geo-parser-reads-past-mapped-file-without-sentinel-bo.patch` adds bounds validation in `src/stream/ngx_stream_geo_module.c` so the loader:
- verifies each `ngx_stream_variable_value_t` header is fully inside the mapped file before reading `vv->data`
- validates each aligned advance derived from record length before moving the cursor
- ensures the terminating sentinel is present within bounds
- confirms the subsequent ranges table fits inside the mapped file before table reads begin