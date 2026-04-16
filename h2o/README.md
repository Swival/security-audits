# H2O Audit Findings

Security audit of the h2o HTTP server. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 25** -- High: 14, Medium: 9, Low: 2

## Findings

### HTTP/1 serialization

| # | Finding | Severity |
|---|---------|----------|
| [005](005-crlf-injection-in-serialized-request-headers.md) | CRLF injection in serialized request headers | High |
| [006](006-crlf-injection-in-request-target-and-host-header.md) | CRLF injection in HTTP/1 request target and Host header | High |
| [014](014-response-splitting-via-unsanitized-reason-phrase.md) | Response splitting via unsanitized reason phrase | High |
| [015](015-response-splitting-via-unsanitized-response-headers.md) | Response header CRLF injection blocked | High |
| [016](016-informational-responses-share-the-same-header-injection-flaw.md) | Informational response serialization permits header injection | High |

### HTTP/3 datagrams

| # | Finding | Severity |
|---|---------|----------|
| [003](003-datagram-flow-id-parser-accepts-invalid-suffixes.md) | Datagram flow ID parser accepts invalid suffixes | Medium |
| [004](004-uninitialized-datagram-flow-id-used-for-non-tunnel-streams.md) | Uninitialized datagram flow ID on ordinary HTTP/3 streams | High |

### HPACK / HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [017](017-unchecked-64-bit-shift-from-remote-digest-bits.md) | Unchecked remote digest bit-width permits 64-bit shift UB | High |
| [018](018-lookup-performs-undefined-shift-on-zero-capacity-digest.md) | Lookup undefined shift on zero-capacity digest | High |
| [028](028-hpack-strings-emitted-without-json-escaping.md) | HPACK debug JSON omits string escaping | Medium |

### FastCGI

| # | Finding | Severity |
|---|---------|----------|
| [007](007-temporary-fastcgi-socket-directory-remains-undeleted.md) | Temporary FastCGI socket directory leak on spawn failure | Low |
| [008](008-unlimited-header-buffering-before-parse-completes.md) | Unlimited FastCGI Header Buffering | Medium |

### URL / authority parsing

| # | Finding | Severity |
|---|---------|----------|
| [023](023-non-digit-port-suffix-accepted-as-valid-authority.md) | Non-digit port suffix accepted as valid authority | Medium |
| [024](024-empty-port-is-normalized-to-port-zero.md) | Empty port accepted as port zero | Medium |
| [027](027-port-ivar-truncates-silently-to-16-bits.md) | Port ivar truncates silently to 16 bits | Medium |

### Connection management

| # | Finding | Severity |
|---|---------|----------|
| [011](011-dispose-frees-pool-targets-before-async-close-callback-runs.md) | Dispose races leased socket close callback | High |
| [019](019-pending-requests-are-dropped-during-reconnect-window.md) | Pending requests dropped during reconnect | Medium |

### Socket I/O

| # | Finding | Severity |
|---|---------|----------|
| [009](009-wrong-buffer-terminated-before-getaddrinfo.md) | Wrong service buffer left unterminated before getaddrinfo | High |
| [020](020-imported-socket-leaks-fd-on-uv-tcp-open-failure.md) | Imported socket import failure leaks ownership and crashes caller | Medium |
| [021](021-write-path-ignores-uv-write-failure-and-loses-completion.md) | Write path drops completion on synchronous uv_write error | High |

### WebSocket

| # | Finding | Severity |
|---|---------|----------|
| [022](022-upgrade-proceeds-after-unchecked-wslay-initialization-failur.md) | Upgrade continues after failed wslay context init | High |

### Redis

| # | Finding | Severity |
|---|---------|----------|
| [001](001-streaming-redis-channel-never-marks-unsubscribe-state.md) | Streaming Redis channel never marks unsubscribe state | Medium |
| [026](026-redis-command-callback-leaks-command-context.md) | Redis command callback retains native command context until GC | Medium |

### Memory

| # | Finding | Severity |
|---|---------|----------|
| [025](025-receiver-removal-memmove-writes-past-vector-end.md) | Receiver removal shifts array the wrong direction | High |

### Logging

| # | Finding | Severity |
|---|---------|----------|
| [013](013-access-log-writes-ignore-i-o-failures.md) | Access log write failures are silently ignored | Low |
