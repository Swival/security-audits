# LibreSSL libcrypto Audit Findings

Security audit of LibreSSL's libcrypto, the cryptography library underneath libssl. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 37** -- High: 24, Medium: 13

## Findings

### Entropy and CSPRNG seeding

| # | Finding | Severity |
|---|---------|----------|
| [008](008-getentropy-succeeds-with-non-os-fallback-entropy.md) | getentropy succeeds with non-OS fallback entropy (AIX) | High |
| [009](009-getentropy-falls-back-to-non-os-entropy.md) | getentropy falls back to non-OS entropy (HP-UX) | High |
| [010](010-getentropy-succeeds-after-entropy-sources-fail.md) | getentropy succeeds after entropy sources fail (Linux) | High |
| [011](011-entropy-source-fails-open-to-system-state-hash.md) | Entropy source fails open to system-state hash (macOS) | High |
| [012](012-getentropy-succeeds-after-kernel-entropy-failure.md) | getentropy succeeds after kernel entropy failure (Solaris) | High |

### X.509 path validation

| # | Finding | Severity |
|---|---------|----------|
| [003](003-ip-verifier-accepts-trailing-garbage.md) | IP verifier accepts trailing garbage | High |
| [004](004-delta-crl-can-satisfy-full-revocation-coverage.md) | Delta CRL can satisfy full revocation coverage | High |
| [006](006-inherited-asid-skips-issuer-resource-absence.md) | Inherited ASID skips issuer resource absence | High |
| [007](007-wrong-purpose-certificates-pass-verification.md) | Wrong-purpose certificates pass verification | High |
| [033](033-embedded-nul-bypasses-dns-name-constraints.md) | Embedded NUL bypasses DNS name constraints | High |
| [034](034-embedded-nul-bypasses-email-name-constraints.md) | Embedded NUL bypasses email name constraints | High |
| [035](035-invalid-certificates-can-pass-ca-purpose-check.md) | Invalid certificates can pass CA-purpose check | High |

### ASN.1 encoding and decoding

| # | Finding | Severity |
|---|---------|----------|
| [013](013-empty-csr-attribute-set-dereferences-null.md) | Empty CSR attribute set dereferences NULL | Medium |
| [018](018-multipart-boundary-accepts-prefixed-delimiter-lines.md) | Multipart boundary accepts prefixed delimiter lines | Medium |
| [020](020-sequence-length-signed-integer-overflow.md) | Sequence length signed integer overflow | High |
| [021](021-set-of-length-signed-integer-overflow.md) | Set-of length signed integer overflow | High |
| [024](024-utf8-output-length-counter-overflows.md) | UTF8 output length counter overflows | Medium |
| [025](025-terminator-byte-addition-overflows-allocation-size.md) | Terminator byte addition overflows allocation size | Medium |

### Symmetric cipher modes

| # | Finding | Severity |
|---|---------|----------|
| [015](015-unchecked-cfb-state-indexes-past-iv.md) | Unchecked CFB state indexes past IV | High |
| [029](029-cbc-decrypt-reads-past-partial-trailing-ciphertext.md) | CBC decrypt reads past partial trailing ciphertext | Medium |
| [030](030-zero-length-gcm-tag-authenticates-successfully.md) | Zero-length GCM tag authenticates successfully | High |

### RSA

| # | Finding | Severity |
|---|---------|----------|
| [032](032-copied-rsa-pss-contexts-drop-verification-restrictions.md) | Copied RSA-PSS contexts drop verification restrictions | High |
| [041](041-asn-1-octet-string-signatures-accept-trailing-bytes.md) | ASN.1 OCTET STRING signatures accept trailing bytes | High |

### CMS

| # | Finding | Severity |
|---|---------|----------|
| [014](014-pwri-unwrap-reads-past-short-stream-cipher-encrypted-keys.md) | PWRI unwrap reads past short stream-cipher encrypted keys | High |
| [027](027-signer-info-retains-freed-pkey-context.md) | Signer info retains freed pkey context | Medium |

### Legacy ciphers

| # | Finding | Severity |
|---|---------|----------|
| [022](022-high-bit-salt-indexes-past-con-salt.md) | High-bit salt indexes past con_salt (DES) | Medium |
| [028](028-zero-bit-cfb-causes-infinite-loop.md) | Zero-bit CFB causes infinite loop (DES) | Medium |
| [038](038-negative-key-length-writes-before-key-schedule.md) | Negative key length writes before key schedule (RC2) | High |
| [039](039-out-of-range-ofb-num-leaks-stack-byte.md) | Out-of-range OFB num leaks stack byte (RC2) | Medium |

### Big numbers and key derivation

| # | Finding | Severity |
|---|---------|----------|
| [001](001-constant-time-modular-exponentiation-downgrades-on-even-modu.md) | Constant-time modular exponentiation downgrades on even moduli | High |
| [002](002-negative-pbkdf2-key-length-becomes-huge-memcpy.md) | Negative PBKDF2 key length becomes huge memcpy | High |

### Other public-key algorithms

| # | Finding | Severity |
|---|---------|----------|
| [019](019-ed25519-accepts-non-canonical-public-keys.md) | Ed25519 accepts non-canonical public keys | High |
| [023](023-sm2-c2-length-overwrites-plaintext-buffer.md) | SM2 C2 length overwrites plaintext buffer | High |

### Key and container formats

| # | Finding | Severity |
|---|---------|----------|
| [016](016-failed-safe-repack-is-treated-as-success.md) | Failed safe repack is treated as success (PKCS12) | Medium |
| [031](031-encrypted-pvk-key-length-checked-after-eight-byte-copy.md) | Encrypted PVK key length checked after eight-byte copy | Medium |

### Configuration and database parsers

| # | Finding | Severity |
|---|---------|----------|
| [005](005-unbounded-config-line-overflows-buffer-offset.md) | Unbounded config line overflows buffer offset | Medium |
| [042](042-unbounded-txt-db-line-growth-exhausts-memory.md) | Unbounded TXT_DB line growth exhausts memory | Medium |
