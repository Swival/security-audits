# zlib Audit Findings

Security audit of zlib, including the core compression library, minizip, DotZLib (.NET bindings), and associated utilities. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 30** -- High: 13, Medium: 16, Low: 1

## Findings

### minizip (ZIP archive handling)

| # | Finding | Severity |
|---|---------|----------|
| [003](003-zip64-extra-field-parser-reads-past-declared-field.md) | ZIP64 extra field parser overreads declared subfield | High |
| [004](004-global-comment-api-dereferences-null-buffer.md) | Global comment API NULL buffer dereference | Medium |
| [006](006-failed-length-read-can-use-uninitialized-size-t-value.md) | Failed length read can use uninitialized size_t value | High |
| [007](007-archive-paths-can-escape-extraction-directory.md) | Archive paths can escape extraction directory | High |
| [008](008-null-pointer-dereference-on-central-header-allocation-failur.md) | Null pointer dereference on central header allocation failure | High |
| [009](009-extra-field-parser-trusts-attacker-controlled-lengths-and-ov.md) | Extra-field parser trusts attacker-controlled lengths and overruns buffers | High |
| [021](021-zip-encryption-uses-legacy-pkware-cipher.md) | ZIP encryption disabled for legacy PKWARE cipher | High |
| [022](022-encrypted-header-leaks-crc-bytes-for-password-verification.md) | Encrypted header leaks CRC bytes for password verification | Medium |
| [023](023-negative-file-length-drives-unchecked-allocation-size.md) | Negative file length drives unchecked allocation size | Medium |
| [024](024-short-filename-suffix-check-reads-before-argument-buffer.md) | Short filename suffix check reads before argument buffer | High |
| [028](028-negative-local-header-offset-written-after-signed-overflow.md) | Repaired archive can claim omitted oversized entry data | Medium |
| [030](030-writes-byte-for-incomplete-trailing-hex-pair.md) | Writes byte for incomplete trailing hex pair | Medium |
| [031](031-non-hex-input-is-accepted-and-emitted.md) | Non-hex input is accepted and emitted | Medium |
| [032](032-consumes-only-one-separator-byte-between-values.md) | Consumes only one separator byte between values | Low |

### DotZLib (.NET bindings)

| # | Finding | Severity |
|---|---------|----------|
| [012](012-pinned-buffer-pointer-truncated-to-32-bit-in-crc32-p-invoke.md) | 64-bit pointer cast breaks checksum updates | High |
| [013](013-nonzero-offset-prevents-any-input-from-being-compressed.md) | Nonzero offset breaks Deflater.Add slice handling | High |
| [014](014-zstream-truncates-native-pointer-fields-to-32-bits.md) | ZStream uses 32-bit managed fields for native pointers | High |
| [015](015-unqualified-zlib1-dll-import-crosses-library-loading-trust-b.md) | Unqualified ZLIB1.dll import crosses library-loading trust boundary | Medium |
| [016](016-offset-skips-all-decompression-work.md) | Offset skips all decompression work | Medium |
| [017](017-consumed-byte-accounting-can-overrun-caller-range.md) | Inflater offset/count slice is under-consumed | High |
| [018](018-finish-resets-stream-after-inflate-error.md) | Finish hides inflate failure by resetting state | Medium |

### gzlog

| # | Finding | Severity |
|---|---------|----------|
| [001](001-lock-ownership-check-can-delete-another-process-s-lock.md) | Lock ownership check can delete another process's lock | Medium |
| [002](002-user-controlled-path-enables-symlink-clobbering-of-sidecar-f.md) | User-controlled sidecar path allows symlink clobbering | Medium |
| [025](025-missing-input-file-still-finalizes-modified-gzip.md) | Missing final input silently commits a rewritten gzip | Medium |

### gzjoin

| # | Finding | Severity |
|---|---------|----------|
| [010](010-output-write-failures-are-silently-ignored.md) | Output write failures return success | Medium |
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
