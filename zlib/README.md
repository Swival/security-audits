# zlib Audit Findings

Security audit of zlib, including the core compression library, minizip, DotZLib (.NET bindings), and associated utilities. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 18** -- High: 8, Medium: 10, Low: 0

## Findings

### minizip (ZIP archive handling)

| # | Finding | Severity |
|---|---------|----------|
| [003](003-zip64-extra-field-parser-reads-past-declared-field.md) | ZIP64 extra field parser overreads declared subfield | High |
| [004](004-global-comment-api-dereferences-null-buffer.md) | Global comment API NULL buffer dereference | Medium |
| [006](006-failed-length-read-can-use-uninitialized-size-t-value.md) | Failed length read can use uninitialized size_t value | High |
| [007](007-archive-paths-can-escape-extraction-directory.md) | Archive paths can escape extraction directory | High |
| [009](009-extra-field-parser-trusts-attacker-controlled-lengths-and-ov.md) | Extra-field parser trusts attacker-controlled lengths and overruns buffers | High |
| [021](021-zip-encryption-uses-legacy-pkware-cipher.md) | ZIP encryption disabled for legacy PKWARE cipher | High |
| [022](022-encrypted-header-leaks-crc-bytes-for-password-verification.md) | Encrypted header leaks CRC bytes for password verification | Medium |
| [023](023-negative-file-length-drives-unchecked-allocation-size.md) | Negative file length drives unchecked allocation size | Medium |
| [024](024-short-filename-suffix-check-reads-before-argument-buffer.md) | Short filename suffix check reads before argument buffer | High |
| [028](028-negative-local-header-offset-written-after-signed-overflow.md) | Repaired archive can claim omitted oversized entry data | Medium |

### DotZLib (.NET bindings)

| # | Finding | Severity |
|---|---------|----------|
| [015](015-unqualified-zlib1-dll-import-crosses-library-loading-trust-b.md) | Unqualified ZLIB1.dll import crosses library-loading trust boundary | Medium |

### gzlog

| # | Finding | Severity |
|---|---------|----------|
| [001](001-lock-ownership-check-can-delete-another-process-s-lock.md) | Lock ownership check can delete another process's lock | Medium |
| [002](002-user-controlled-path-enables-symlink-clobbering-of-sidecar-f.md) | User-controlled sidecar path allows symlink clobbering | Medium |

### gzjoin

| # | Finding | Severity |
|---|---------|----------|
| [011](011-trailer-crc-is-taken-from-input-without-validation.md) | Trailer CRC validation missing in joined members | Medium |

### iostream2 (C++ bindings)

| # | Finding | Severity |
|---|---------|----------|
| [005](005-unchecked-length-prefixed-read-overflows-caller-buffer.md) | Unchecked length-prefixed read overflows caller buffer | High |

### zlib core

| # | Finding | Severity |
|---|---------|----------|
| [019](019-fixed-huffman-table-initialization-races-across-threads.md) | Fixed Huffman table initialization races across threads | Medium |
| [020](020-insecure-fallback-overflows-gzprintf-buffer.md) | Insecure vsprintf fallback overflows gzprintf buffer | High |
| [026](026-unsynchronized-lazy-huffman-table-initialization.md) | Unsynchronized lazy Huffman table initialization | Medium |
