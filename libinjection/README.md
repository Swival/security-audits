# libinjection Audit Findings

Security audit of libinjection, a SQL injection and XSS detection library. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 11** -- High: 6, Medium: 5

## Findings

### XSS detection (libinjection_xss.c)

| # | Finding | Severity |
|---|---------|----------|
| [004](004-any-on-prefix-matches-a-listed-event-handler.md) | Any `on*` prefix event match causes false-positive XSS detection | High |

### Log scanner (logscanner2.py)

| # | Finding | Severity |
|---|---------|----------|
| [001](001-malformed-query-pair-crashes-scanner.md) | Malformed query pair crashes scanner | Medium |
| [002](002-non-numeric-apache-byte-count-aborts-parsing.md) | Non-numeric Apache byte count aborts parsing | Medium |
| [003](003-invalid-apache-timestamp-aborts-parsing.md) | Invalid Apache timestamp aborts parsing | Medium |

### Test server (nullserver.py)

| # | Finding | Severity |
|---|---------|----------|
| [005](005-unauthenticated-shutdown-endpoint-exits-server.md) | Unauthenticated shutdown endpoint exits server | High |
| [006](006-shutdown-can-crash-before-file-initialization.md) | Shutdown crashes when fd is uninitialized | Medium |

### Test driver (testdriver.c)

| # | Finding | Severity |
|---|---------|----------|
| [007](007-unbounded-strcat-overflows-fixed-test-buffers.md) | Unbounded strcat overflows fixed test buffers | High |
| [008](008-token-printer-can-overflow-g-actual.md) | Token printer can overflow g_actual | High |
| [009](009-html5-token-formatter-uses-unbounded-sprintf.md) | HTML5 token formatter overflows fixed-size output buffer | High |

### HTML5 CLI (html5_cli.c)

| # | Finding | Severity |
|---|---------|----------|
| [010](010-url-decode-writes-one-byte-past-heap-buffer.md) | URL decode heap off-by-one | High |
| [011](011-missing-argument-check-after-f-option.md) | Missing -f argument check causes null pointer crash | Medium |
