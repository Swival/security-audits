# H2O Audit Findings

Security audit of the H2O HTTP/1, HTTP/2, and HTTP/3 server. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 32** -- High: 18, Medium: 11, Low: 3 (1 fixed upstream as of 2026-05-26)

## Findings

### HTTP/1 CRLF injection and response splitting

| # | Finding | Severity |
|---|---------|----------|
| [005](005-crlf-injection-in-serialized-request-headers.md) | CRLF injection in serialized request headers | High |
| [006](006-crlf-injection-in-request-target-and-host-header.md) | CRLF injection in HTTP/1 request target and Host header | High |
| [014](014-response-splitting-via-unsanitized-reason-phrase.md) | Response splitting via unsanitized reason phrase | High |
| [015](015-response-splitting-via-unsanitized-response-headers.md) | Response header CRLF injection | High |
| [016](016-informational-responses-share-the-same-header-injection-flaw.md) | Informational response serialization permits header injection | High |

### HTTP/1 framing and smuggling

| # | Finding | Severity |
|---|---------|----------|
| [031](031-chunked-parser-accepts-truncated-response.md) | Chunked HTTP/1 client treats truncated response as complete | Medium |
| [039](039-conflicting-content-length-headers-are-accepted.md) | Conflicting Content-Length headers are accepted | Medium |

### HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [017](017-unchecked-64-bit-shift-from-remote-digest-bits.md) | Unchecked remote digest bit-width permits 64-bit shift UB | High |
| [018](018-lookup-performs-undefined-shift-on-zero-capacity-digest.md) | Lookup undefined shift on zero-capacity digest | High |
| [028](028-hpack-strings-emitted-without-json-escaping.md) | HPACK debug JSON omits string escaping | Medium |
| [033](033-continuation-stream-id-can-switch-response-streams.md) | HTTP/2 client accepts CONTINUATION on a different stream | Medium |

### HTTP/3 / QPACK / datagram

| # | Finding | Severity |
|---|---------|----------|
| [003](003-datagram-flow-id-parser-accepts-invalid-suffixes.md) | Datagram flow ID parser accepts invalid suffixes | Medium |
| [004](004-uninitialized-datagram-flow-id-used-for-non-tunnel-streams.md) | Uninitialized datagram flow ID on ordinary HTTP/3 streams | High |
| [029](029-unauthenticated-quic-forwarded-header-spoofing.md) | Unauthenticated QUIC forwarded-header spoofing on public listener | High |
| [034](034-incomplete-connect-udp-capsules-accumulate-without-size-limit.md) | Incomplete CONNECT-UDP capsules accumulate without size limit | Medium |
| [036](036-huffman-literal-name-uses-attacker-sized-alloca.md) | QPACK Huffman literal name uses attacker-sized `alloca` | Medium |
| [037](037-blocked-stream-compaction-reads-past-vector.md) | QPACK blocked-stream compaction reads past vector | Low |

### URL and authority parsing

| # | Finding | Severity |
|---|---------|----------|
| [023](023-non-digit-port-suffix-accepted-as-valid-authority.md) | Non-digit port suffix accepted as valid authority | Medium |
| [024](024-empty-port-is-normalized-to-port-zero.md) | Empty port accepted as port zero | Medium |

### Memory and resource lifetime

| # | Finding | Severity |
|---|---------|----------|
| [011](011-dispose-frees-pool-targets-before-async-close-callback-runs.md) | Dispose races leased socket close callback | High |
| [021](021-write-path-ignores-uv-write-failure-and-loses-completion.md) | Write path drops completion on synchronous `uv_write` error | High |
| [025](025-receiver-removal-memmove-writes-past-vector-end.md) | Receiver removal shifts array the wrong direction | High |
| [038](038-piped-response-error-path-uses-disposed-generator.md) | Piped response error path dereferences a disposed generator | High |
| [040](040-request-close-use-after-free-in-status-collection.md) | Status JSON collector frees request-pool storage still used by async collection | High |

### WebSocket upgrade

| # | Finding | Severity |
|---|---------|----------|
| [022](022-upgrade-proceeds-after-unchecked-wslay-initialization-failur.md) | Upgrade continues after failed wslay context init | High |

### FastCGI

| # | Finding | Severity |
|---|---------|----------|
| [008](008-unlimited-header-buffering-before-parse-completes.md) | Unlimited FastCGI header buffering before parse completes | Medium |
| [035](035-unbounded-buffering-of-incomplete-fastcgi-response-headers.md) | Unbounded buffering of incomplete FastCGI response headers | Medium |

### MRuby, Redis, and DNS

| # | Finding | Severity |
|---|---------|----------|
| [001](001-streaming-redis-channel-never-marks-unsubscribe-state.md) | Streaming Redis channel never marks unsubscribe state | Medium |
| [009](009-wrong-buffer-terminated-before-getaddrinfo.md) | Wrong service buffer left unterminated before `getaddrinfo` (fixed) | High |
| [032](032-redis-ticket-updater-leaks-non-string-replies-in-retry-loop.md) | Redis ticket updater leaks non-string replies inside no-delay retry loop | Low |
| [041](041-unbounded-recursive-redis-reply-decoding.md) | Unbounded recursive decoding of nested Redis replies in mruby | Low |

### CLI client (`h2o-httpclient`)

| # | Finding | Severity |
|---|---------|----------|
| [030](030-connect-udp-listener-binds-all-interfaces.md) | `-X` CONNECT-UDP listener binds all interfaces | Low |
