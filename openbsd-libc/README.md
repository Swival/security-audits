# OpenBSD libc Audit Findings

Security audit of OpenBSD's libc, the C standard library shipped with OpenBSD. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 21** -- High: 15, Medium: 6

## Findings

### Sun RPC and XDR

| # | Finding | Severity |
|---|---------|----------|
| [001](001-nonmatching-rpc-replies-bypass-call-timeout.md) | Nonmatching RPC replies bypass call timeout | Medium |
| [003](003-accepted-rpc-connection-null-dereferences-failed-transporter.md) | Accepted RPC connection null-dereferences failed transporter | Medium |
| [008](008-ignored-realloc-failure-enables-oversized-body-read.md) | Ignored realloc failure enables oversized body read | High |
| [010](010-uint-max-string-length-desynchronizes-xdr-decoding.md) | UINT_MAX string length desynchronizes XDR decoding | High |
| [011](011-unknown-rpc-procedure-terminates-service.md) | Unknown RPC procedure terminates service | High |
| [022](022-opaque-verifier-padding-leaks-inline-buffer-bytes.md) | Opaque verifier padding leaks inline buffer bytes | Medium |

### YP / NIS

| # | Finding | Severity |
|---|---------|----------|
| [004](004-getpwent-copies-oversized-yp-passwd-values.md) | getpwent copies oversized YP passwd values | High |
| [005](005-yp-lookup-permits-one-byte-buffer-overflow.md) | YP lookup permits one-byte buffer overflow | High |
| [012](012-yp-enumeration-overflows-group-line-buffer.md) | YP enumeration overflows group line buffer | High |
| [013](013-yp-wildcard-lookup-overflows-group-line-buffer.md) | YP wildcard lookup overflows group line buffer | High |
| [014](014-yp-named-include-overflows-group-line-buffer.md) | YP named include overflows group line buffer | High |

### Hash database

| # | Finding | Severity |
|---|---------|----------|
| [006](006-database-header-can-underallocate-segment-directory.md) | Database header can underallocate segment directory | High |
| [007](007-database-header-controls-bitmap-memset-length.md) | Database header controls bitmap memset length | High |
| [015](015-disk-page-count-drives-byte-swap-past-page.md) | Disk page count drives byte-swap past page | High |
| [016](016-on-disk-key-count-overwrites-icdb-object.md) | On-disk key count overwrites icdb object | High |

### Resolver

| # | Finding | Severity |
|---|---------|----------|
| [009](009-dns-response-parser-accepts-unrelated-answer-names.md) | DNS response parser accepts unrelated answer names | Medium |

### rcmd

| # | Finding | Severity |
|---|---------|----------|
| [017](017-stderr-callback-trusts-any-reserved-port-peer.md) | stderr callback trusts any reserved-port peer | Medium |

### Regular expressions

| # | Finding | Severity |
|---|---------|----------|
| [018](018-nested-ere-groups-exhaust-parser-stack.md) | Nested ERE groups exhaust parser stack | Medium |

### printf

| # | Finding | Severity |
|---|---------|----------|
| [019](019-positional-printf-index-writes-past-type-table.md) | Positional printf index writes past type table | High |
| [020](020-oversized-positional-index-writes-past-type-table.md) | Oversized positional index writes past type table | High |

### stdio

| # | Finding | Severity |
|---|---------|----------|
| [023](023-byte-counted-capacity-overflows-wide-stream-buffer.md) | Byte-counted capacity overflows wide stream buffer | High |
