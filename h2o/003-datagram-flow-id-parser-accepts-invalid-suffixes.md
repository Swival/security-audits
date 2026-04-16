# Datagram flow ID parser accepts invalid suffixes

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/http3/server.c:1006`

## Summary
`CONNECT-UDP` request handling accepted malformed `datagram-flow-id` values containing a valid numeric prefix followed by non-digits. The parser stopped at the first non-digit, kept the parsed prefix, and allowed request processing to continue. As a result, inputs such as `123x` were treated as valid and normalized to `123` instead of being rejected.

## Provenance
- Verified from the provided reproduction and source inspection
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- A `CONNECT-UDP` request includes a `datagram-flow-id` header whose value is non-empty and starts with one or more ASCII digits followed by at least one non-digit byte

## Proof
- In `handle_input_expect_headers`, the `datagram-flow-id` parser iterated over header bytes, accumulated decimal digits, and `break`ed on the first non-digit at `lib/http3/server.c:1006`
- The parser did not require full consumption of the header value and did not reject trailing non-digit data
- The partially parsed integer was then passed into `handle_input_expect_headers_process_connect`, which stored it in `stream->datagram_flow_id` and continued tunnel setup
- The reproduced behavior showed `datagram-flow-id: 123x` being accepted, the stream registered under flow ID `123`, and the response reflecting the normalized numeric prefix rather than rejecting the malformed request
- This behavior is reachable directly from client-controlled QPACK-decoded request headers

## Why This Is A Real Bug
The protocol field is intended to carry a numeric flow identifier, so accepting trailing non-digit bytes violates input syntax and weakens boundary validation. This is observable server behavior, not a theoretical concern: malformed requests are accepted and rewritten into valid state. That creates a protocol-validation bypass and can cause inconsistent interpretation across components that do enforce strict parsing.

## Fix Requirement
Reject `datagram-flow-id` unless the entire field is composed only of digits, and reject empty values.

## Patch Rationale
The patch in `003-datagram-flow-id-parser-accepts-invalid-suffixes.patch` tightens parsing in `lib/http3/server.c` so the header is accepted only when every byte is an ASCII digit and at least one digit is present. This preserves valid behavior while preventing partial parses and silent normalization of malformed values.

## Residual Risk
None

## Patch
- File: `003-datagram-flow-id-parser-accepts-invalid-suffixes.patch`
- Change: enforce full-string digit validation for `datagram-flow-id` and reject empty or suffix-tainted values during `CONNECT-UDP` header processing