# OpenBSD libexec Audit Findings

Security audit of programs shipped under OpenBSD's `libexec` tree. These are not user-facing tools but helper binaries invoked by other parts of the system: BSD authentication helpers, the dynamic linker, RPC services, mail and spam infrastructure, and the traditional C preprocessor. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 17** -- High: 3, Medium: 14

## Findings

### BSD authentication helpers

| # | Finding | Severity |
|---|---------|----------|
| [001](001-malformed-challenge-attribute-causes-backwards-parser-walk.md) | Malformed challenge attribute causes backwards parser walk | High |
| [002](002-oversized-state-attribute-leaks-stack-bytes.md) | Oversized State attribute leaks stack bytes | Medium |
| [003](003-unterminated-response-scans-past-stack-buffer.md) | Unterminated response scans past stack buffer | Medium |
| [004](004-yubikey-counter-check-updates-non-atomically.md) | YubiKey counter check updates non-atomically | High |
| [009](009-malformed-ldap-control-dereferences-missing-child-elements.md) | Malformed LDAP control dereferences missing child elements | Medium |
| [010](010-malformed-page-control-dereferences-absent-value-element.md) | Malformed page control dereferences absent value element | Medium |
| [011](011-invalid-encoded-page-control-dereferences-failed-ber-parse.md) | Invalid encoded page control dereferences failed BER parse | Medium |

### Dynamic linker (ld.so)

| # | Finding | Severity |
|---|---------|----------|
| [012](012-elf-program-headers-read-past-fixed-header-buffer.md) | ELF program headers read past fixed header buffer | Medium |
| [013](013-elf-program-headers-are-read-past-the-header-buffer.md) | ELF program headers are read past the header buffer | Medium |
| [014](014-elf-without-load-segments-dereferences-null-load-list.md) | ELF without load segments dereferences null load list | Medium |
| [018](018-unchecked-elf-relocation-type-indexes-static-tables.md) | Unchecked ELF relocation type indexes static tables | Medium |

### RPC services

| # | Finding | Severity |
|---|---------|----------|
| [005](005-negative-quota-id-leaks-uninitialized-quota-reply-fields.md) | Negative quota id leaks uninitialized quota reply fields | High |
| [019](019-legacy-rusers-reply-uses-wrong-xdr-type.md) | Legacy rusers reply uses wrong XDR type | Medium |

### Spam and mail infrastructure

| # | Finding | Severity |
|---|---------|----------|
| [006](006-remote-feed-can-force-unbounded-decompression.md) | Remote feed can force unbounded decompression | Medium |

### Network daemons

| # | Finding | Severity |
|---|---------|----------|
| [017](017-client-controlled-response-address-enables-udp-reflection.md) | Client-controlled response address enables UDP reflection | Medium |

### Traditional C preprocessor

| # | Finding | Severity |
|---|---------|----------|
| [007](007-signed-division-overflow-in-if-evaluator.md) | Signed division overflow in `#if` evaluator | Medium |
| [008](008-signed-remainder-overflow-in-if-evaluator.md) | Signed remainder overflow in `#if` evaluator | Medium |
