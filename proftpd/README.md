# ProFTPD Audit Findings

Security audit of ProFTPD, an FTP server for Unix-like systems. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 17** -- High: 9, Medium: 8

## Findings

### Chroot and filesystem

| # | Finding | Severity |
|---|---------|----------|
| [003](003-chroot-guard-accepts-traversal-into-protected-directories.md) | Chroot guard accepts traversal into protected directories | High |
| [008](008-recursive-list-follows-symlink-cycles.md) | Recursive LIST follows symlink cycles | Medium |
| [017](017-ftp-username-traverses-directory-lastlog-path.md) | FTP username traverses directory lastlog path | High |

### Controls (mod_ctrls)

| # | Finding | Severity |
|---|---------|----------|
| [004](004-controls-request-length-wraps-allocation.md) | Controls request length wraps allocation | High |
| [005](005-partial-control-command-blocks-transfer-worker.md) | Partial control command blocks transfer worker | Medium |
| [010](010-help-control-bypasses-action-acl.md) | Help control bypasses action ACL | Medium |

### Access control and ACLs

| # | Finding | Severity |
|---|---------|----------|
| [006](006-missing-class-makes-passive-foreign-address-filter-fail-open.md) | Missing class makes passive foreign-address filter fail open | Medium |
| [016](016-solaris-group-acl-denial-falls-through-to-other.md) | Solaris group ACL denial falls through to other | High |

### Authentication and privileges

| # | Finding | Severity |
|---|---------|----------|
| [009](009-getgrset-group-parsing-overflows-fixed-gid-array.md) | getgrset group parsing overflows fixed gid array | High |
| [018](018-mixed-privilege-nesting-retains-root-euid.md) | Mixed privilege nesting retains root EUID | High |

### Stats and accounting

| # | Finding | Severity |
|---|---------|----------|
| [001](001-rnto-stats-destination-before-authorization.md) | RNTO stats destination before authorization | Medium |
| [002](002-one-value-median-reads-past-array.md) | One-value median reads past array | Medium |
| [007](007-maxtransfersperuser-skips-matching-transfers.md) | MaxTransfersPerUser skips matching transfers | Medium |

### mod_redis

| # | Finding | Severity |
|---|---------|----------|
| [011](011-odd-hgetall-array-reads-past-reply-elements.md) | Odd HGETALL array reads past reply elements | High |
| [012](012-short-sentinel-address-reply-reads-past-elements.md) | Short sentinel address reply reads past elements | High |
| [013](013-short-sentinel-masters-entry-reads-past-elements.md) | Short sentinel masters entry reads past elements | High |

### Logging

| # | Finding | Severity |
|---|---------|----------|
| [014](014-raw-rfc1413-ident-permits-transfer-log-injection.md) | Raw RFC1413 ident permits transfer-log injection | Medium |
