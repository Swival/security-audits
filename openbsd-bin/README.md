# OpenBSD Userland Audit Findings

Security audit of OpenBSD userland programs and libraries: the `httpd` web server, the `doas` privilege escalation tool, the `smtpd` mail daemon, the `lpd` print spooler, the `ftp-proxy` and `dhcrelay` network services, the `make` build tool, the `m4` macro processor, and the `libtls` and `libelf` libraries that ship with the base system. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 34** -- High: 9, Medium: 21, Low: 4

Findings are numbered per component, so a couple of numbers are reused across the different tables below.

## Findings

### httpd

| # | Finding | Severity |
|---|---------|----------|
| [001](001-full-basic-auth-credential-buffer-is-scanned-past-its-end.md) | Full basic-auth credential buffer is scanned past its end | Medium |
| [002](002-failed-basic-auth-attempts-spoof-remote-user-in-logs.md) | Failed basic-auth attempts spoof remote user in logs | Low |
| [009](009-malformed-fastcgi-header-bypasses-http-response-framing.md) | Malformed FastCGI header bypasses HTTP response framing | Medium |

### doas

| # | Finding | Severity |
|---|---------|----------|
| [003](003-long-argv-hides-executed-arguments-from-audit-log.md) | Long argv hides executed arguments from audit log | Low |

### ftp-proxy

| # | Finding | Severity |
|---|---------|----------|
| [004](004-pipelining-clears-pasv-rewrite-state.md) | Pipelining clears PASV rewrite state | Low |

### smtpd

| # | Finding | Severity |
|---|---------|----------|
| [005](005-envelope-fields-leak-on-every-delivery.md) | Envelope fields leak on every delivery | Medium |
| [006](006-wildcard-source-block-is-bypassed.md) | Wildcard source block is bypassed | High |
| [011](011-certificate-verifier-ignores-crl-file.md) | Certificate verifier ignores CRL file | High |
| [012](012-unbounded-lmtp-reply-line-allocation.md) | Unbounded LMTP reply line allocation | Medium |

### lpr / lpd

| # | Finding | Severity |
|---|---------|----------|
| [008](008-print-job-fields-inject-mail-recipients.md) | Print job fields inject mail recipients | Low |
| [014](014-negative-indent-writes-before-line-buffer.md) | Negative indent writes before line buffer | High |
| [015](015-control-file-hostname-rewrite-writes-past-command-buffer.md) | Control-file hostname rewrite writes past command buffer | High |

### libtls

| # | Finding | Severity |
|---|---------|----------|
| [010](010-ocsp-unknown-status-accepted.md) | OCSP UNKNOWN status accepted | High |
| [017](017-trailing-dot-wildcard-matches-top-level-domain.md) | Trailing-dot wildcard matches top-level domain | High |

### libelf

| # | Finding | Severity |
|---|---------|----------|
| [013](013-bsd-extended-archive-name-overreads-backing-buffer.md) | BSD extended archive name overreads backing buffer | Medium |
| [018](018-partial-move-entry-read-crosses-data-boundary.md) | Partial MOVE entry read crosses data boundary | Medium |
| [019](019-partial-move-entry-write-crosses-data-boundary.md) | Partial MOVE entry write crosses data boundary | High |
| [020](020-truncated-rel-entry-passes-read-bounds-check.md) | Truncated REL entry passes read bounds check | Medium |
| [021](021-truncated-rel-entry-passes-write-bounds-check.md) | Truncated REL entry passes write bounds check | High |
| [022](022-truncated-rela-entry-passes-bounds-check.md) | Truncated RELA entry passes bounds check | Medium |
| [023](023-truncated-rela-update-writes-past-buffer.md) | Truncated RELA update writes past buffer | Medium |
| [024](024-truncated-symbol-entry-overread.md) | Truncated symbol entry overread | Medium |
| [025](025-truncated-symbol-entry-overwrite.md) | Truncated symbol entry overwrite | High |
| [026](026-bsd-symbol-table-size-check-allows-out-of-bounds-read.md) | BSD symbol table size check allows out-of-bounds read | Medium |

### dhcrelay

| # | Finding | Severity |
|---|---------|----------|
| [016](016-udp-payload-may-extend-past-ip-packet.md) | UDP payload may extend past IP packet | Medium |

### make

| # | Finding | Severity |
|---|---------|----------|
| [002](002-all-space-archive-name-underflows-buffer.md) | All-space archive name underflows buffer | Medium |
| [003](003-unterminated-svr4-long-name-returned.md) | Unterminated SVR4 long name returned | Medium |
| [004](004-cyclic-suffix-rules-cause-unbounded-implicit-source-expansio.md) | Cyclic suffix rules cause unbounded implicit-source expansion | Medium |
| [005](005-empty-global-substitution-never-advances.md) | Empty global substitution never advances | Medium |
| [006](006-suffix-substitution-underflows-match-offset.md) | Suffix substitution underflows match offset | Medium |
| [009](009-unchecked-separator-causes-path-buffer-overflow.md) | Unchecked separator causes path buffer overflow | Medium |

### m4

| # | Finding | Severity |
|---|---------|----------|
| [001](001-substr-offset-causes-out-of-bounds-read.md) | `substr` offset causes out-of-bounds read | Medium |
| [007](007-undefine-frees-live-macro-definition.md) | `undefine` frees live macro definition | Medium |
| [008](008-popdef-frees-live-macro-definition.md) | `popdef` frees live macro definition | Medium |
