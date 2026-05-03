# quicly Audit Findings

Security audit of quicly, a QUIC protocol implementation in C. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 3** -- High: 1, Medium: 2

## Findings

### Connection ID management

| # | Finding | Severity |
|---|---------|----------|
| [001](001-retired-cid-shift-copies-too-few-survivors.md) | Retired CID shift copies too few survivors | Medium |

### CLI server

| # | Finding | Severity |
|---|---------|----------|
| [002](002-double-slash-request-reads-absolute-files.md) | Double-slash request reads absolute files | High |

### Congestion control

| # | Finding | Severity |
|---|---------|----------|
| [003](003-delayed-acks-zero-congestion-increment-divisor.md) | Delayed ACKs zero congestion increment divisor | Medium |
