# CRLF injection in serialized request headers

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/common/http1client.c:572`
- `lib/common/http1client.c:879`
- `lib/core/headers.c:71`
- `lib/core/headers.c:77`
- `src/httpclient.c:644`
- `src/httpclient.c:893`

## Summary
The HTTP/1 request serializer writes caller-supplied header names and values directly into the outbound request buffer and only appends `\r\n` afterward. Because neither the shared header helpers nor the HTTP/1 client path reject embedded carriage return or line feed bytes, an attacker-controlled header value can terminate the current header line and inject additional HTTP/1 headers or request content.

## Provenance
- Verified from the provided reproducer and source review
- Swival Security Scanner: https://swival.dev

## Preconditions
- Caller supplies a header value containing `\r` or `\n`

## Proof
- `on_connect` forwards caller-controlled headers into request startup at `lib/common/http1client.c:879`.
- `start_request` reaches `build_request`, where `APPEND_HEADER` serializes `(h)->value.base` and `(h)->value.len` verbatim, then appends `"\r\n"` at `lib/common/http1client.c:572`.
- Shared helpers `h2o_add_header` and `h2o_add_header_by_str` only store provided buffers and lengths, with no CR/LF filtering at `lib/core/headers.c:71` and `lib/core/headers.c:77`.
- The shipped client tool accepts arbitrary `-H name:value`, stores the bytes after the first colon, and passes them into the HTTP client via `src/httpclient.c:644` and `src/httpclient.c:893`.
- A header value containing `\r\nInjected: x` therefore survives to HTTP/1 serialization and produces an extra header line on the wire.

## Why This Is A Real Bug
HTTP/1.1 header framing is line-based. Any unescaped `\r` or `\n` inside a serialized header name or value breaks the intended field boundary and changes the request structure seen by the peer. This enables request header injection and can extend to request smuggling-style effects depending on downstream parsing. The issue is reachable through shipped code, not only through hypothetical embedders.

## Fix Requirement
Reject header names and values containing `\r` or `\n` before `APPEND_HEADER` serializes them in the HTTP/1 client path.

## Patch Rationale
The patch adds explicit CR/LF validation in the HTTP/1 request-building path so malformed header names or values are refused before bytes are written to the outbound request buffer. This is the narrowest effective fix for the proven bug: it hardens the vulnerable serializer without changing unrelated header storage behavior or the already separate HTTP/2 and HTTP/3 validation paths.

## Residual Risk
None

## Patch
- Patch file: `005-crlf-injection-in-serialized-request-headers.patch`
- The patch enforces rejection of header names and values containing `\r` or `\n` in `lib/common/http1client.c` before HTTP/1 serialization occurs.