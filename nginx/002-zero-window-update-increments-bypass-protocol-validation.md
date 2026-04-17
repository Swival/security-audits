# Zero WINDOW_UPDATE increments accepted as valid HTTP/2 frames

## Classification
- Type: invariant violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_proxy_v2_module.c:1708`
- `src/http/modules/ngx_http_proxy_v2_module.c:3575`
- `src/http/modules/ngx_http_proxy_v2_module.c:3587`
- `src/http/modules/ngx_http_proxy_v2_module.c:1934`
- `src/http/modules/ngx_http_proxy_v2_module.c:2134`

## Summary
`ngx_http_proxy_v2_parse_window_update()` accepts a `WINDOW_UPDATE` frame whose 31-bit increment is zero. The code parses the field, clears the reserved bit, and only rejects values that would overflow flow-control accounting before applying the increment to either the stream or connection send window. Because `0` is not rejected, malformed upstream peers can send an invalid HTTP/2 `WINDOW_UPDATE` that nginx treats as valid instead of terminating the stream or connection with `PROTOCOL_ERROR`.

## Provenance
- Verified by reproduction against the affected parser and control-frame dispatch paths in `src/http/modules/ngx_http_proxy_v2_module.c`
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- A malicious upstream can send HTTP/2 `WINDOW_UPDATE` frames

## Proof
- Input reaches `ngx_http_proxy_v2_parse_window_update()` from upstream-controlled frame bytes.
- The parser assembles `ctx->window_update` from the frame payload and masks the reserved bit.
- The existing validation only rejects oversized increments before adding the value to `ctx->send_window` or `ctx->connection->send_window`.
- No branch rejects `ctx->window_update == 0`, so a zero increment is accepted as a valid frame.
- This path is reachable through control-frame processing during both header handling and later response processing, including closed-stream handling, via `src/http/modules/ngx_http_proxy_v2_module.c:1934` and `src/http/modules/ngx_http_proxy_v2_module.c:2134`.
- Reproduction confirmed the acceptance points at `src/http/modules/ngx_http_proxy_v2_module.c:3575` and `src/http/modules/ngx_http_proxy_v2_module.c:3587`.

## Why This Is A Real Bug
RFC 7540 section 6.9 requires an endpoint that receives `WINDOW_UPDATE` with an increment of `0` to treat it as `PROTOCOL_ERROR` on the relevant stream or connection. Accepting the frame violates a mandatory protocol invariant. While the zero increment does not itself alter flow-control counters, it still allows an invalid upstream peer to remain connected and bypass nginx's protocol validation logic.

## Fix Requirement
Reject `WINDOW_UPDATE` frames with `ctx->window_update == 0` in `ngx_http_proxy_v2_parse_window_update()` before any flow-control accounting, and surface the existing protocol error handling for stream-scoped versus connection-scoped frames.

## Patch Rationale
The correct fix is a narrow parser-side validation check immediately after decoding the 31-bit increment and before updating any window state. That matches the RFC requirement, preserves existing accounting behavior for valid increments, and ensures malformed upstream frames fail at the earliest authoritative validation point.

## Residual Risk
None

## Patch
Patched in `002-zero-window-update-increments-bypass-protocol-validation.patch`.