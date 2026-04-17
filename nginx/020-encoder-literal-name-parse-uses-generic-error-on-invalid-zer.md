# Encoder literal-name zero-length parse returns wrong protocol error

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/http/v3/ngx_http_v3_parse.c:1015`

## Summary
A zero-length name in an encoder-stream Insert With Literal Name instruction reaches `ngx_http_v3_parse_field_iln()` and is rejected with plain `NGX_ERROR` instead of a protocol-specific QPACK error. This violates the parser's error-code contract and causes nginx to close the HTTP/3 connection with `H3_GENERAL_PROTOCOL_ERROR` rather than `QPACK_ENCODER_STREAM_ERROR`.

## Provenance
- Verified from the provided finding and reproduction notes
- Reference: https://swival.dev

## Preconditions
- A peer sends an encoder-stream Insert With Literal Name instruction with a zero-length literal name

## Proof
Untrusted encoder-stream input is parsed by `ngx_http_v3_parse_encoder()`, which dispatches the Insert With Literal Name path into `ngx_http_v3_parse_field_iln()` at `src/http/v3/ngx_http_v3_parse.c:1015`. After `ngx_http_v3_parse_prefix_int(..., 5, ...)` decodes the name length, the function checks `st->literal.length == 0` and returns `NGX_ERROR`. That generic failure propagates through the HTTP/3 unidirectional stream error handling and is finalized at `src/http/v3/ngx_http_v3_uni.c:255` as `H3_GENERAL_PROTOCOL_ERROR` (`0x101`). The reproduced trace confirms nginx emits that code for this input. RFC 9204 defines encoder-stream instruction decode failures as `QPACK_ENCODER_STREAM_ERROR` (`0x201`), so the observed result is incorrect.

## Why This Is A Real Bug
The condition is directly reachable from peer-controlled encoder-stream bytes and deterministically produces the wrong wire-visible error code. This is not cosmetic: peers and diagnostics rely on the distinction between generic HTTP/3 protocol failure and QPACK encoder-stream failure, and nearby parser paths already preserve that distinction by returning specific HTTP/3/QPACK error codes for invalid input.

## Fix Requirement
Return the appropriate QPACK protocol error code for a zero-length literal name in the Insert With Literal Name parser path, instead of `NGX_ERROR`.

## Patch Rationale
The patch changes the zero-length-name rejection in `ngx_http_v3_parse_field_iln()` to return the protocol-specific encoder-stream parse error. This preserves existing validation behavior while restoring consistent parser error semantics and ensuring the connection is closed with `QPACK_ENCODER_STREAM_ERROR`.

## Residual Risk
None

## Patch
- Patch file: `020-encoder-literal-name-parse-uses-generic-error-on-invalid-zer.patch`
- Change: replace the generic `NGX_ERROR` return in `src/http/v3/ngx_http_v3_parse.c:1015` with the appropriate QPACK encoder-stream error code for this invalid instruction path