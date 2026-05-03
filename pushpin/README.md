# Pushpin Audit Findings

Security audit of [Pushpin](https://pushpin.org/), a reverse proxy designed to push real-time data to long-lived HTTP and WebSocket connections through its GRIP control protocol. Each finding includes a detailed write-up and a patch. Reproducers for several findings live under [`poc/`](poc/).

## Summary

**Total findings: 8** -- High: 3, Medium: 5

## Findings

### HTTP/1 framing

| # | Finding | Severity |
|---|---------|----------|
| [012](012-conflicting-request-content-length-uses-last-value.md) | Conflicting request Content-Length uses last value | High |

### Proxy and SockJS

| # | Finding | Severity |
|---|---------|----------|
| [007](007-fragmented-sockjs-websocket-frames-accumulate-without-total-.md) | Fragmented SockJS WebSocket frames accumulate without total cap | High |
| [015](015-jsonp-callback-parameter-injects-javascript.md) | JSONP callback parameter injects JavaScript | Medium |

### GRIP control protocol

| # | Finding | Severity |
|---|---------|----------|
| [022](022-grip-instruct-response-headers-allow-crlf-injection.md) | grip-instruct response headers allow CRLF injection | Medium |
| [023](023-grip-instruct-reason-phrase-allows-response-splitting.md) | grip-instruct reason phrase allows response splitting | Medium |
| [024](024-grip-status-reason-phrase-allows-response-splitting.md) | Grip-Status reason phrase allows response splitting | Medium |

### CORS

| # | Finding | Severity |
|---|---------|----------|
| [030](030-cors-origin-check-reflects-arbitrary-credentialed-origins.md) | CORS origin check reflects arbitrary credentialed origins | High |

### Connection manager

| # | Finding | Severity |
|---|---------|----------|
| [001](001-unix-socket-permissions-are-applied-after-bind.md) | Unix socket permissions are applied after bind | Medium |
