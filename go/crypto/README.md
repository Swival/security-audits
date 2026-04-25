# Go crypto Audit Findings

Security audit of the Go standard library `crypto` package. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 69** -- High: 3, Medium: 41, Low: 25

## Findings

### TLS

| # | Finding | Severity |
|---|---------|----------|
| [001](001-nil-session-inserted-for-missing-key.md) | Nil session inserted for missing key | Low |
| [005](005-context-cancellation-can-close-completed-handshake.md) | Context cancellation can close completed handshake | Medium |
| [010](010-echconfiglist-parser-can-loop-forever.md) | ECHConfigList parser can loop forever | Medium |
| [011](011-trailing-ech-extension-bytes-accepted.md) | Trailing ECH extension bytes accepted | Low |
| [014](014-start-error-leaves-blocking-state.md) | Start error leaves blocking state | Low |
| [016](016-hrr-allows-psk-identity-changes.md) | HRR allows PSK identity changes | Low |
| [017](017-unchecked-ech-hash-clone.md) | Unchecked ECH hash clone | Medium |
| [027](027-shared-xor-nonce-race.md) | Shared XOR nonce race | Medium |
| [050](050-sha-384-marked-non-approved.md) | SHA-384 marked non-approved | Medium |
| [051](051-hkdf-label-length-truncation.md) | HKDF label length truncation | Medium |
| [052](052-oversized-ekm-context-allocates-before-validation.md) | Oversized EKM context allocates before validation | Low |
| [053](053-negative-ekm-length-panics.md) | Negative EKM length panics | Low |
| [059](059-cleanup-uses-mutable-der-key.md) | Cleanup uses mutable DER key | Low |
| [072](072-peer-transport-parameters-alias-caller-buffer.md) | Peer transport parameters alias caller buffer | Medium |

### X.509

| # | Finding | Severity |
|---|---------|----------|
| [006](006-zero-certificate-serial-accepted.md) | Zero certificate serial accepted | Low |
| [007](007-crl-issuer-key-not-enforced.md) | CRL issuer key not enforced | Medium |
| [018](018-null-policy-failure-reports-success-status.md) | NULL policy failure reports success status | Low |
| [019](019-null-chain-failure-reports-success-status.md) | NULL chain failure reports success status | Low |
| [020](020-certificatepolicies-not-enforced-without-explicit-policy.md) | CertificatePolicies not enforced without explicit policy | Medium |
| [038](038-email-constraints-match-subdomains.md) | Email constraints match subdomains | Medium |
| [039](039-trailing-der-accepted.md) | Trailing DER accepted | Low |
| [041](041-unsupported-ekus-panic.md) | Unsupported EKUs panic | Medium |
| [060](060-negative-requireexplicitpolicy-accepted.md) | Negative requireExplicitPolicy accepted | Medium |
| [061](061-negative-inhibitpolicymapping-accepted.md) | Negative inhibitPolicyMapping accepted | Medium |
| [062](062-invalid-pkcs-1-version-accepted.md) | Invalid PKCS#1 version accepted | Low |
| [063](063-multi-prime-version-mismatch-accepted.md) | Multi-prime version mismatch accepted | Low |

### ECDSA

| # | Finding | Severity |
|---|---------|----------|
| [023](023-public-key-aliases-caller-buffer.md) | Public key aliases caller buffer | Medium |
| [024](024-private-scalar-exposed-mutably.md) | Private scalar exposed mutably | Medium |
| [025](025-public-key-exposed-mutably.md) | Public key exposed mutably | Medium |
| [028](028-nil-coordinates-panic.md) | Nil coordinates panic | Low |
| [029](029-nil-scalar-panics.md) | Nil scalar panics | Low |
| [034](034-add-violates-infinity-precondition.md) | Add violates infinity precondition | Medium |
| [035](035-scalarmult-violates-infinity-precondition.md) | ScalarMult violates infinity precondition | Medium |
| [056](056-p-521-accepts-overlong-signature-scalars.md) | P-521 accepts overlong signature scalars | Medium |
| [066](066-non-invertible-signature-panics-verification.md) | Non-invertible signature panics verification | Medium |
| [067](067-invalid-order-loops-forever.md) | Invalid order loops forever | Medium |
| [073](073-nil-inverse-dereference-on-non-invertible-nonce.md) | Nil inverse dereference on non-invertible nonce | Medium |

### ECDH

| # | Finding | Severity |
|---|---------|----------|
| [042](042-nil-remote-key-panic.md) | Nil remote key panic | Low |
| [045](045-mutable-private-scalar-exposure.md) | Mutable private scalar exposure | Medium |
| [046](046-mutable-public-key-exposure.md) | Mutable public key exposure | Medium |
| [068](068-unknown-public-curve-panics.md) | Unknown public curve panics | Medium |
| [069](069-unknown-private-curve-panics.md) | Unknown private curve panics | Medium |

### RSA

| # | Finding | Severity |
|---|---------|----------|
| [021](021-zero-exponent-returns-base.md) | Zero exponent returns base | Medium |
| [064](064-unchecked-oaep-mgf-hash-approval.md) | Unchecked OAEP MGF hash approval | Medium |
| [065](065-unchecked-oaep-mgf-hash-approval.md) | Unchecked OAEP MGF hash approval | Medium |
| [070](070-mgf-hash-bypasses-fips-approval.md) | MGF hash bypasses FIPS approval | Medium |
| [074](074-nil-oaep-options-panic-before-validation.md) | Nil OAEP options panic before validation | Medium |
| [075](075-zero-hash-panics-in-pkcs1v15-fips-checks.md) | Zero hash panics in PKCS1v15 FIPS checks | Medium |

### AES / GCM

| # | Finding | Severity |
|---|---------|----------|
| [012](012-wrong-generated-assembly-target.md) | Wrong generated assembly target | Low |
| [031](031-tail-decryption-over-reads-ciphertext.md) | Tail decryption over-reads ciphertext | Medium |
| [032](032-counter-nonce-skips-allowed.md) | Counter nonce skips allowed | Low |
| [033](033-xor-counter-nonce-skips-allowed.md) | XOR counter nonce skips allowed | Low |
| [043](043-empty-aes-key-panics.md) | Empty AES key panics | Low |
| [044](044-ctr-counter-wrap-is-unchecked.md) | CTR counter wrap is unchecked | High |

### HPKE

| # | Finding | Severity |
|---|---------|----------|
| [008](008-concurrent-seal-nonce-reuse.md) | Concurrent seal nonce reuse | High |
| [009](009-seal-counter-wraps.md) | Seal counter wraps | Low |

### HKDF

| # | Finding | Severity |
|---|---------|----------|
| [047](047-oversized-hkdf-output-panics.md) | Oversized HKDF output panics | Medium |
| [048](048-negative-hkdf-length-panics.md) | Negative HKDF length panics | Low |

### PBKDF2

| # | Finding | Severity |
|---|---------|----------|
| [049](049-pbkdf2-accepts-nonpositive-iterations.md) | PBKDF2 accepts nonpositive iterations | Medium |

### SHA-3

| # | Finding | Severity |
|---|---------|----------|
| [058](058-absorbing-state-allows-full-buffer.md) | Absorbing state allows full buffer | Low |

### DRBG

| # | Finding | Severity |
|---|---------|----------|
| [022](022-unsynchronized-global-reader.md) | Unsynchronized global reader | Medium |

### ML-KEM

| # | Finding | Severity |
|---|---------|----------|
| [026](026-imported-keys-skip-pct.md) | Imported keys skip PCT | Medium |

### FIPS 140 testing

| # | Finding | Severity |
|---|---------|----------|
| [002](002-short-randnonce-ciphertext-panics.md) | Short randNonce ciphertext panics | Medium |
| [003](003-oversized-cmac-panics.md) | Oversized CMAC panics | Medium |
| [004](004-oversized-rsa-exponent-panics.md) | Oversized RSA exponent panics | Medium |
| [013](013-file-descriptor-leak-on-write-error.md) | File descriptor leak on write error | Low |
| [015](015-siggen-mu-argument-is-ignored-as-context.md) | sigGen mu argument is ignored as context | Medium |
| [040](040-empty-samples-panic.md) | Empty samples panic | Low |
| [071](071-unbounded-request-argument-count-can-exhaust-memory.md) | Unbounded request argument count can exhaust memory | High |
