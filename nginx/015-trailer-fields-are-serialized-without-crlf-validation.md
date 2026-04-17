# Trailer fields are serialized without CRLF validation

## Classification
- Severity: medium
- Type: validation gap
- Confidence: certain

## Affected Locations
- `src/http/modules/ngx_http_chunked_filter_module.c:257`

## Summary
`ngx_http_chunked_create_trailers()` serializes `r->headers_out.trailers` into the HTTP/1 chunked trailer block by copying trailer names and values verbatim, then appending `CRLF`. Before the patch, it performed no validation for embedded `CR` or `LF` bytes in either field. If any module or configuration path placed such bytes into a trailer key or value, nginx emitted raw line breaks inside the trailer section, structurally splitting trailer fields and enabling malformed or injected trailer lines.

## Provenance
- Verified by reproduction against the affected code path and patched locally
- Scanner source: https://swival.dev

## Preconditions
- Response trailers contain `CR` or `LF` bytes in the trailer name or value
- `r->expect_trailers` reaches the chunked trailer serialization path

## Proof
In `ngx_http_chunked_create_trailers()`, trailer bytes originate from `r->headers_out.trailers`. The function first computes output length, then copies `header[i].key.data` and `header[i].value.data` directly into the output buffer with `ngx_copy`, followed by `":" SP` and terminating `CRLF`. No validation occurs before length calculation or copying at `src/http/modules/ngx_http_chunked_filter_module.c:257`.

Reproduction confirmed that when a trailer value contains embedded `\r\n`, nginx serializes those bytes as raw trailer text. The emitted trailer block is therefore split into multiple logical trailer lines or otherwise malformed, which is a direct HTTP/1 response-splitting condition within the trailer section.

## Why This Is A Real Bug
HTTP/1 trailer fields are line-based metadata. Allowing raw `CR` or `LF` inside a serialized trailer name or value breaks message framing for the trailer block itself. Even if common upstream parsing paths reject such bytes, the sink remains vulnerable because nginx also supports locally constructed trailers. The reproduced case shows the serializer will emit attacker-dangerous line delimiters if unsafe bytes enter `r->headers_out.trailers`, so the flaw is real at the output boundary.

## Fix Requirement
Reject or sanitize trailer names and values containing `CR` or `LF` before trailer length accounting and serialization, so the chunked filter never emits structurally unsafe trailer bytes.

## Patch Rationale
The patch hardens `ngx_http_chunked_create_trailers()` by validating each trailer key and value for `CR`/`LF` before including it in the serialized trailer block. Unsafe entries are not emitted, which preserves trailer framing and removes the response-splitting sink at the final serialization boundary regardless of the upstream source of trailer data.

## Residual Risk
None

## Patch
Patched in `015-trailer-fields-are-serialized-without-crlf-validation.patch`.