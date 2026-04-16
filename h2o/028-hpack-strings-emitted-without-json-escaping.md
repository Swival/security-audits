# HPACK debug JSON omits string escaping

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/http2/http2_debug_state.c:78`

## Summary
HPACK table entries are serialized into the HTTP/2 debug-state JSON without JSON escaping. Header names are validated as tokens and are not practically exploitable through this path, but header values permit `"` and `\` as well as other bytes that must be escaped in JSON. A peer can therefore inject HPACK-indexed values that make the emitted debug JSON invalid or attacker-controlled in content.

## Provenance
- Reproduced from the verified finding and confirmed against the implementation and validator behavior.
- Source file: `lib/http2/http2_debug_state.c`
- Scanner reference: https://swival.dev

## Preconditions
- HTTP/2 debug state is requested.
- HPACK output is enabled.
- The attacker can cause a header value to be inserted into `conn->_input_header_table` or `conn->_output_header_table`.
- The debug endpoint is then queried on the same connection.

## Proof
At `lib/http2/http2_debug_state.c:78`, `append_header_table_chunks` emits HPACK entry fields into JSON using raw string formatting with `"%.*s"` for both name and value. No JSON escaping is applied before writing those bytes into the response buffer.

Reproduction showed:
- Header names are constrained by `h2o_hpack_validate_header_name` and cannot practically carry quotes, backslashes, or control bytes.
- Header values are accepted by `h2o_hpack_validate_header_value` and may contain printable ASCII, tab, and obs-text, including `"` and `\`.
- A peer can send an incrementally indexed header such as `foo: "` or `foo: \`, causing the value to enter the HPACK dynamic table.
- When debug state is later rendered with HPACK enabled, that value is embedded into a JSON string unescaped, breaking JSON structure or altering interpreted content.

## Why This Is A Real Bug
The output is advertised and consumed as JSON. Emitting unescaped `"` or `\` inside JSON string literals violates JSON syntax and breaks parser expectations. This is a concrete integrity bug in a diagnostic interface reachable from peer-controlled HTTP/2 traffic under the stated conditions. It does not require memory corruption to be security-relevant.

## Fix Requirement
Escape HPACK header names and values according to JSON string encoding rules before appending them to the debug output.

## Patch Rationale
The patch updates `lib/http2/http2_debug_state.c` to JSON-escape serialized HPACK strings before writing them into the debug-state response. This preserves valid output for all header-table contents while keeping the existing structure and behavior unchanged apart from correct encoding.

## Residual Risk
None

## Patch
- Patched file: `lib/http2/http2_debug_state.c`
- Patch artifact: `028-hpack-strings-emitted-without-json-escaping.patch`