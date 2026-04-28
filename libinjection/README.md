# libinjection Audit Findings

Security audit of libinjection, a SQL injection and XSS detection library. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 5** -- High: 5, Medium: 0

## Findings

### Test server (nullserver.py)

| # | Finding | Severity |
|---|---------|----------|
| [005](005-unauthenticated-shutdown-endpoint-exits-server.md) | Unauthenticated shutdown endpoint exits server | High |

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
