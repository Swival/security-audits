# BoringSSL Audit Findings

Security audit of BoringSSL, Google's fork of OpenSSL. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 12** -- High: 4, Medium: 8

## Findings

### Trust Token

| # | Finding | Severity |
|---|---------|----------|
| [001](001-short-metadata-keys-are-accepted-and-stored.md) | Short metadata keys are accepted and stored | High |
| [003](003-issuer-private-key-parser-accepts-trailing-bytes.md) | Issuer private key parser accepts trailing bytes | Medium |

### ASN.1 / DER encoding

| # | Finding | Severity |
|---|---------|----------|
| [021](021-negative-bit-index-writes-before-buffer-start.md) | Negative bit index writes before buffer start | High |
| [022](022-negative-bit-index-reads-before-buffer-start.md) | Negative bit index reads before buffer start | Medium |
| [023](023-mismatched-any-tag-is-re-encoded-from-asn1-string-metadata.md) | Mismatched ANY tag re-encoded from ASN1_STRING metadata | Medium |

### Symmetric ciphers (RC2, RC4, AES-EAX)

| # | Finding | Severity |
|---|---------|----------|
| [016](016-seal-accepts-ciphertext-lengths-open-always-rejects.md) | AES-EAX seal/open length limit mismatch | Medium |
| [024](024-cbc-decrypt-reads-past-short-final-block.md) | RC2-CBC decrypt reads past short final block | High |
| [027](027-zero-length-key-causes-out-of-bounds-read.md) | RC4 zero-length key out-of-bounds read | High |

### KDF and PEM parsing

| # | Finding | Severity |
|---|---------|----------|
| [010](010-pbkdf2-block-counter-can-wrap-for-oversized-keys.md) | PBKDF2 block counter wraps for oversized keys | Medium |
| [026](026-missing-delimiter-check-before-iv-parsing.md) | Missing DEK-Info delimiter check before IV parsing | Medium |

### EVP key handling

| # | Finding | Severity |
|---|---------|----------|
| [025](025-raw-key-getters-dereference-missing-method-table.md) | Raw key getters dereference missing method table | Medium |

### X.509 verification

| # | Finding | Severity |
|---|---------|----------|
| [035](035-poison-state-can-be-cleared-by-copying-clean-params.md) | Poison state cleared by clean param copy | Medium |
