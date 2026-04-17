# WASI stderr exposed in HTTP 500

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/wasix/src/runners/wcgi/handler.rs:140`
- Reachability nuance: `lib/wasix/src/runners/wcgi/runner.rs:196`
- Reachability nuance: `lib/wasix/src/runners/dcgi/runner.rs:53`

## Summary
When `propagate_stderr` is enabled, the WCGI handler buffers raw guest stderr and, if any bytes are present, returns an HTTP `500` whose body is exactly those bytes. This sends untrusted process output directly to the client without sanitization, redaction, or truncation.

## Provenance
- Verified from reproduced behavior and source inspection
- Scanner: [Swival Security Scanner](https://swival.dev)

## Preconditions
- `propagate_stderr` is enabled
- The WCGI/DCGI guest writes attacker-influenced data to stderr
- A request reaches the handler while stderr is non-empty

## Proof
- `consume_stderr()` buffers guest stderr when `propagate_stderr` is enabled.
- `handle()` checks that buffered stderr before completing the normal response path.
- If stderr is non-empty, `handle()` returns HTTP `500` and uses `body_from_data(stderr)` for the response body.
- `body_from_data()` wraps the bytes as the HTTP body; it does not sanitize, escape, or redact them.
- This stderr error path overrides an otherwise valid stdout-generated CGI response, so any non-empty stderr is reflected to the client.

## Why This Is A Real Bug
This is a direct trust-boundary crossing from guest process output to an external HTTP response. Stderr commonly contains diagnostics, stack traces, request-derived values, secrets, or other sensitive operational data. Returning it verbatim to clients causes information disclosure and can reflect attacker-controlled content. Reachability is confirmed: WCGI makes it configurable, and DCGI enables it by default, making the issue directly reachable there.

## Fix Requirement
Do not include guest stderr in HTTP response bodies. Preserve stderr only in server-side logging or internal diagnostics, and return a generic `500` body to the client.

## Patch Rationale
The patch removes stderr reflection from the HTTP response path in `lib/wasix/src/runners/wcgi/handler.rs` and replaces it with a generic internal error response. This preserves failure signaling while preventing untrusted guest diagnostics from crossing the server/client boundary. The change matches the intended fix outline and maintains safe behavior regardless of whether stderr is attacker-influenced.

## Residual Risk
None

## Patch
- Patch file: `004-wasi-stderr-is-returned-verbatim-in-http-500.patch`
- Effect: guest stderr is no longer embedded in HTTP `500` bodies; clients receive a generic error instead.