# Zero-length literal names lose protocol-specific HTTP/3/QPACK error codes

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/http/v3/ngx_http_v3_parse.c:674`
- `src/http/v3/ngx_http_v3_parse.c:1048`

## Summary
Zero-length literal-name fields are parsed from peer-controlled QPACK bytes, but the parser returns plain `NGX_ERROR` instead of a protocol-specific HTTP/3/QPACK error code. This causes malformed request HEADERS to fall into a generic internal-error path and malformed encoder-stream instructions to be translated into `NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR` rather than the correct QPACK-class error.

## Provenance
- Verified finding reproduced from scanner report
- Scanner source: https://swival.dev

## Preconditions
- A peer sends a literal-name field representation with a decoded name length of `0`
- The input reaches either `ngx_http_v3_parse_field_l()` or `ngx_http_v3_parse_field_iln()`

## Proof
In `src/http/v3/ngx_http_v3_parse.c:674`, `ngx_http_v3_parse_field_l()` decodes the literal name length with `ngx_http_v3_parse_prefix_int()`. When `st->literal.length == 0`, it returns `NGX_ERROR`.
In `src/http/v3/ngx_http_v3_parse.c:1048`, `ngx_http_v3_parse_field_iln()` performs the same check and also returns `NGX_ERROR`.

These bytes are peer-controlled:
- Request HEADERS reach the field-line parser through the QPACK decoder path.
- Encoder-stream instructions reach the same parser via the unidirectional stream parser.

Observed impact from reproduction:
- On request HEADERS, the plain `NGX_ERROR` propagates into a generic internal-error handling path instead of a QPACK decompression failure.
- On the encoder stream, `ngx_http_v3_parse_uni()` propagates the nonpositive parse result into `src/http/v3/ngx_http_v3_uni.c:240`, which maps it to `NGX_HTTP_V3_ERR_GENERAL_PROTOCOL_ERROR` instead of the QPACK-specific encoder-stream error.

Nearby malformed-input paths already return explicit `NGX_HTTP_V3_ERR_*` values, and NGINX uses QPACK-specific errors for comparable decode failures elsewhere.

## Why This Is A Real Bug
A zero-length literal name is invalid input, and the parser is in the only position that knows the precise failure class. Returning plain `NGX_ERROR` discards that classification, so later layers mis-handle the same malformed peer input as a generic internal/protocol failure. This is externally triggerable, changes the wire-visible error behavior, and weakens protocol compliance and diagnostics.

## Fix Requirement
Return protocol-specific `NGX_HTTP_V3_ERR_*` values for zero-length literal names:
- `NGX_HTTP_V3_ERR_DECOMPRESSION_FAILED` for field-section decoding paths
- `NGX_HTTP_V3_ERR_ENCODER_STREAM_ERROR` for encoder-stream instruction decoding paths

## Patch Rationale
The patch updates the zero-length name checks in the literal-field parsers to preserve the correct QPACK failure classification at the point of detection. This keeps malformed request HEADERS on the decompression-failed path and malformed encoder-stream instructions on the encoder-stream-error path, matching surrounding parser behavior and RFC-defined error taxonomy.

## Residual Risk
None

## Patch
Patched `src/http/v3/ngx_http_v3_parse.c` so the zero-length literal-name checks return protocol-specific errors instead of `NGX_ERROR`, and saved the fix as `019-zero-length-literal-names-return-generic-error-instead-of-ht.patch`.