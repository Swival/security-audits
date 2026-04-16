# Informational response serialization permits header injection

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/http1.c:847`
- `lib/core/proxy.c:662`
- `lib/core/proxy.c:677`
- `lib/core/proxy.c:678`

## Summary
`finalostream_send_informational` serializes HTTP/1 informational responses using `req->res.reason` and `req->res.headers` without rejecting embedded `\r` or `\n`. This allows attacker-controlled bytes in informational header names or values to break header boundaries and inject additional HTTP/1 response lines before `h2o_socket_write`.

## Provenance
- Verified from the supplied reproducer and source inspection in `lib/http1.c:847`
- Reachable via proxy propagation in `lib/core/proxy.c:662`, `lib/core/proxy.c:677`, and `lib/core/proxy.c:678`
- Reference: Swival Security Scanner, https://swival.dev

## Preconditions
- Application sets informational reason or header value from untrusted input

## Proof
`finalostream_send_informational` builds the status line with `HTTP/1.1 %d %s\r\n` using `req->res.reason`, then appends headers via `flatten_res_headers` in `lib/http1.c:847`. `flatten_res_headers` copies header names and values verbatim and terminates each field with `\r\n`; no CR/LF filtering occurs before the buffer is sent with `h2o_socket_write`.

The reproduced path is proxying: `lib/core/proxy.c:678` assigns upstream informational headers directly into `src_req->res.headers`, after setup in `lib/core/proxy.c:662` and `lib/core/proxy.c:677`. If an upstream informational header value contains bytes such as `\r\nX-Evil: 1\r\n`, the downstream HTTP/1 informational response emits those bytes unchanged, producing injected header lines.

The reason phrase is likewise unsanitized in the serializer. The supplied reproducer directly demonstrates header injection; reason-phrase injection remains reachable anywhere application code assigns attacker-controlled data to `req->res.reason` before an informational response is sent.

## Why This Is A Real Bug
HTTP/1 response framing depends on CRLF-delimited header lines. Copying untrusted informational header names, header values, or reason text into the serialized response without CR/LF validation lets an attacker create new header fields or alter response content seen by downstream clients or intermediaries. This is a concrete response-splitting primitive, not a theoretical parser discrepancy.

## Fix Requirement
Reject or sanitize `\r` and `\n` in informational response reason text and informational header names/values before serialization in the HTTP/1 path.

## Patch Rationale
The patch in `016-informational-responses-share-the-same-header-injection-flaw.patch` closes the issue at the serialization boundary by ensuring informational responses cannot emit CR/LF-bearing reason text or header fields. Fixing at this sink protects both direct application use and proxy-propagated informational responses without depending on every caller to validate inputs correctly.

## Residual Risk
None

## Patch
- Added validation/sanitization for informational HTTP/1 serialization in `lib/http1.c`
- Prevented CR/LF-bearing informational reason text from being written into the status line
- Prevented CR/LF-bearing informational header names and values from being serialized by `flatten_res_headers` consumers in the informational path
- Covered the reproduced proxy-reachable case where upstream informational headers are forwarded into `src_req->res.headers` and emitted downstream