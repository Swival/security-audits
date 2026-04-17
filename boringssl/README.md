# BoringSSL Audit Findings

Security audit of BoringSSL, Google's fork of OpenSSL. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 15** -- High: 4, Medium: 11

## Findings

### Trust Token

| # | Finding | Severity |
|---|---------|----------|
| [001](001-short-metadata-keys-are-accepted-and-stored.md) | Short metadata keys are accepted and stored | High |
| [003](003-issuer-private-key-parser-accepts-trailing-bytes.md) | Issuer private key parser accepts trailing bytes | Medium |

### ASN.1

| # | Finding | Severity |
|---|---------|----------|
| [021](021-negative-bit-index-writes-before-buffer-start.md) | Negative bit index writes before buffer start | High |
| [022](022-negative-bit-index-reads-before-buffer-start.md) | Negative bit index reads before buffer start | Medium |
| [023](023-mismatched-any-tag-is-re-encoded-from-asn1-string-metadata.md) | Mismatched ANY tag is re-encoded from ASN1_STRING metadata | Medium |

### Cipher

| # | Finding | Severity |
|---|---------|----------|
| [024](024-cbc-decrypt-reads-past-short-final-block.md) | CBC decrypt reads past short final block | High |
| [027](027-zero-length-key-causes-out-of-bounds-read.md) | Zero-length key causes out-of-bounds read | High |

### AEAD

| # | Finding | Severity |
|---|---------|----------|
| [016](016-seal-accepts-ciphertext-lengths-open-always-rejects.md) | Seal accepts ciphertext lengths Open always rejects | Medium |

### EVP

| # | Finding | Severity |
|---|---------|----------|
| [010](010-pbkdf2-block-counter-can-wrap-for-oversized-keys.md) | PBKDF2 block counter can wrap for oversized keys | Medium |
| [017](017-copycontext-leaks-allocated-dst-context-on-copy-failure.md) | CopyContext leaks allocated dst context on copy failure | Medium |
| [025](025-raw-key-getters-dereference-missing-method-table.md) | Raw key getters dereference missing method table | Medium |

### X.509

| # | Finding | Severity |
|---|---------|----------|
| [004](004-requested-extensions-leak-on-error-path.md) | Requested extensions leak on error path | Medium |
| [028](028-revoked-entry-print-errors-are-ignored.md) | Revoked entry print errors are ignored | Medium |
| [035](035-poison-state-can-be-cleared-by-copying-clean-params.md) | Poison state can be cleared by copying clean params | Medium |

### PEM

| # | Finding | Severity |
|---|---------|----------|
| [026](026-missing-delimiter-check-before-iv-parsing.md) | Missing delimiter check before IV parsing | Medium |
