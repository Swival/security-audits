# picotls Audit Findings

Security audit of picotls, a TLS 1.3 implementation in C. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 11** -- High: 7, Medium: 4

## Findings

### TLS 1.2 record path

| # | Finding | Severity |
|---|---------|----------|
| [001](001-tls-1-2-receive-path-suppresses-decryption-errors.md) | TLS 1.2 receive path suppresses decryption errors | High |

### AEAD / AES-GCM

| # | Finding | Severity |
|---|---------|----------|
| [002](002-unchecked-aes-gcm-resize-null-dereference-on-encrypt.md) | Unchecked AES-GCM resize NULL-dereferences on encrypt | High |
| [003](003-setup-reports-success-after-aes-gcm-allocation-failure.md) | Setup reports success after AES-GCM allocation failure | High |
| [010](010-aead-constructor-failure-is-reported-as-success.md) | AEAD constructor failure is reported as success | High |
| [012](012-decrypt-underflows-ciphertext-length-before-tag-split.md) | Decrypt underflows ciphertext length before tag split | High |

### Key generation & ECDH

| # | Finding | Severity |
|---|---------|----------|
| [007](007-key-generation-failure-ignored-before-ecdh.md) | Keygen failure proceeds into ECDH state | Medium |
| [008](008-one-shot-ecdh-ignores-key-generation-failure.md) | One-shot ECDH ignores key generation failure | Medium |

### Signature handling

| # | Finding | Severity |
|---|---------|----------|
| [009](009-signature-generation-failure-ignored.md) | Signature generation failure ignored | Medium |

### RSA key parsing

| # | Finding | Severity |
|---|---------|----------|
| [006](006-rsa-key-bit-parser-reads-past-short-buffer.md) | RSA key-bit parser overreads short DER input | Medium |

### QUIC-LB packet protection

| # | Finding | Severity |
|---|---------|----------|
| [013](013-assert-only-length-guard-allows-mask-index-underflow.md) | Assert-only length guard allows mask index underflow | High |
| [014](014-split-input-overruns-block-buffers-for-oversized-lengths.md) | Split input overruns block buffers for oversized lengths | High |
