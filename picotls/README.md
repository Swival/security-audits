# picotls Audit Findings

Security audit of picotls, a TLS 1.3 protocol library in C. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 7** -- High: 4, Medium: 3

## Findings

### TLS protocol

| # | Finding | Severity |
|---|---------|----------|
| [001](001-tls-1-2-receive-path-suppresses-decryption-errors.md) | TLS 1.2 receive path drops fatal decrypt failures | High |

### AEAD encryption

| # | Finding | Severity |
|---|---------|----------|
| [010](010-aead-constructor-failure-is-reported-as-success.md) | AEAD constructor failure is reported as success | High |
| [012](012-decrypt-underflows-ciphertext-length-before-tag-split.md) | Decrypt length underflow before tag split | High |

### ECDH key exchange

| # | Finding | Severity |
|---|---------|----------|
| [007](007-key-generation-failure-ignored-before-ecdh.md) | Keygen failure proceeds into ECDH state | Medium |
| [008](008-one-shot-ecdh-ignores-key-generation-failure.md) | One-shot ECDH ignores key generation failure | Medium |

### RSA key parsing

| # | Finding | Severity |
|---|---------|----------|
| [006](006-rsa-key-bit-parser-reads-past-short-buffer.md) | RSA key-bit parser reads past short buffer | Medium |

### QUICLB cipher

| # | Finding | Severity |
|---|---------|----------|
| [014](014-split-input-overruns-block-buffers-for-oversized-lengths.md) | Split input overruns block buffers for oversized lengths | High |
