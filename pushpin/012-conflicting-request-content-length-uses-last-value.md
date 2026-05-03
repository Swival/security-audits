# Conflicting Request Content-Length Uses Last Value

## Classification

Request smuggling. Severity: high. Confidence: certain.

## Affected Locations

`src/core/http1/protocol.rs:1128`

## Summary

`ServerProtocol::process_request` accepted multiple request `Content-Length` headers with different values and used the last value encountered. This creates request-framing ambiguity with peers that reject duplicates or choose a different value, enabling HTTP request smuggling across parser boundaries.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An unauthenticated HTTP client can send raw HTTP/1 requests to this parser.
- The proxy forwards requests to a peer that rejects conflicting `Content-Length` headers or chooses another `Content-Length` value.
- The connection can remain persistent so leftover bytes are processed as a later request.

## Proof

`ServerProtocol::recv_request_owned` parses attacker-controlled headers, then calls `process_request`.

Before the patch, the `Content-Length` branch parsed every matching header and unconditionally assigned:

```rust
content_len = Some(len);
```

Therefore, for:

```http
POST / HTTP/1.1
Host: example
Content-Length: 5
Content-Length: 3

abcGET /smuggled HTTP/1.1
Host: example

```

this parser selected `3`, set `BodySize::Known(3)`, set `chunk_left` to `3`, and consumed only `abc` as the body. The remaining `GET /smuggled ...` bytes stayed available for keep-alive reuse.

A peer choosing the first value would instead frame `abcGE` as body. The two parsers disagree on the request boundary, which is the request-smuggling primitive.

Relevant reproduced behavior:
- `src/core/http1/protocol.rs:1128` overwrote earlier `Content-Length` values.
- `src/core/http1/protocol.rs:1155` used the final value as `BodySize::Known(len)`.
- `src/core/http1/protocol.rs:1157` copied the final value into `chunk_left`.
- `src/core/http1/protocol.rs:827` and `src/core/http1/protocol.rs:836` consumed exactly `chunk_left` bytes.
- `src/core/http1/server.rs:136` preserved bytes after the parsed header.
- `src/connmgr/connection.rs:1862` kept the read buffer across keep-alive reuse.

## Why This Is A Real Bug

Conflicting `Content-Length` values are ambiguous request framing metadata. Accepting them and choosing the last value is unsafe because common adjacent HTTP parsers either reject the request or choose a different value. That parser disagreement can turn attacker-supplied body bytes into a second request on a persistent connection.

## Fix Requirement

Reject multiple request `Content-Length` headers unless every parsed value is identical.

## Patch Rationale

The patch records the first parsed request `Content-Length` value and compares each subsequent value against it. If a later value differs, `process_request` returns `Error::InvalidContentLength` before body framing state is set. Identical duplicates remain accepted, preserving valid equivalent framing while removing ambiguity.

## Residual Risk

None

## Patch

```diff
diff --git a/src/core/http1/protocol.rs b/src/core/http1/protocol.rs
index 27c4cb5a..74c68058 100644
--- a/src/core/http1/protocol.rs
+++ b/src/core/http1/protocol.rs
@@ -1125,6 +1125,12 @@ impl<'buf, 'headers> ServerProtocol {
                     Err(_) => return Err(Error::InvalidContentLength),
                 };
 
+                if let Some(prev_len) = content_len {
+                    if prev_len != len {
+                        return Err(Error::InvalidContentLength);
+                    }
+                }
+
                 content_len = Some(len);
             } else if h.name.eq_ignore_ascii_case("Transfer-Encoding") {
                 if h.value == b"chunked" {
```