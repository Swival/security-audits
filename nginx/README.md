# nginx Audit Findings

Security audit of the nginx web server, covering core modules, protocol handling, and platform-specific code paths. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 12** -- High: 8, Medium: 4

## Findings

### Geo module

| # | Finding | Severity |
|---|---------|----------|
| [004](004-binary-geo-loader-reads-variable-records-before-size-validat.md) | Binary geo loader bounds-checks variable and range records before dereference | High |
| [005](005-binary-geo-loader-trusts-unbounded-range-sentinels.md) | Binary geo loader trusts unbounded range sentinels | High |
| [012](012-binary-geo-parser-reads-past-mapped-file-without-sentinel-bo.md) | Binary geo parser reads past mapped file without sentinel bounds check | High |
| [013](013-range-rebasing-loop-dereferences-untrusted-records-before-bo.md) | Range rebasing loop validates record size before dereference | High |

### QUIC / HTTP/3

| # | Finding | Severity |
|---|---------|----------|
| [001](001-upgrade-can-continue-with-inconsistent-quic-socket-state.md) | Abort reload on partial QUIC BPF init failure | High |

### HTTP response filters

| # | Finding | Severity |
|---|---------|----------|
| [008](008-slice-range-construction-can-overflow.md) | Slice range construction can overflow | Medium |
| [015](015-trailer-fields-are-serialized-without-crlf-validation.md) | Trailer fields are serialized without CRLF validation | Medium |

### XSLT filter

| # | Finding | Severity |
|---|---------|----------|
| [009](009-untrusted-xml-enables-external-entity-expansion.md) | Untrusted XML Enables External Entity Expansion | High |

### MP4 module

| # | Finding | Severity |
|---|---------|----------|
| [007](007-negative-offset-adjustment-wraps-32-bit-chunk-offsets.md) | 32-bit stco offset adjustment wraps on rewrite | High |

### Windows platform

| # | Finding | Severity |
|---|---------|----------|
| [016](016-shared-memory-remap-drops-existing-mapping-on-failure.md) | Shared memory remap drops existing mapping on failure | High |
| [017](017-file-info-copies-uninitialized-metadata-on-attribute-lookup-.md) | File info copies uninitialized metadata on attribute lookup failure | Medium |
| [018](018-realpath-stub-returns-input-unchanged.md) | realpath stub returns input unchanged | Medium |
