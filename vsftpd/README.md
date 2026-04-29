# vsftpd Audit Findings

Security audit of vsftpd, a secure FTP daemon for Unix-like systems. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 3** -- High: 3

## Findings

### ptrace sandbox

| # | Finding | Severity |
|---|---------|----------|
| [001](001-read-only-open-sandbox-permits-file-creation.md) | Read-only open sandbox permits file creation | High |

### Prelogin / HTTP mode

| # | Finding | Severity |
|---|---------|----------|
| [002](002-http-get-bypasses-anonymous-prelogin-controls.md) | HTTP GET bypasses anonymous prelogin controls | High |

### TLS / ALPN

| # | Finding | Severity |
|---|---------|----------|
| [003](003-alpn-scanner-accepts-embedded-ftp-outside-protocol-entry.md) | ALPN scanner accepts embedded ftp outside protocol entry | High |
