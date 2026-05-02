# LibreSSL libssl Audit Findings

Security audit of LibreSSL's libssl, the TLS/SSL protocol library. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 3** -- High: 2, Medium: 1

## Findings

### TLS 1.3 handshake

| # | Finding | Severity |
|---|---------|----------|
| [001](001-hrr-extension-hash-omits-length-framing.md) | HRR extension hash omits length framing | High |

### Key exchange

| # | Finding | Severity |
|---|---------|----------|
| [002](002-peer-dhe-parameters-skip-prime-and-generator-validation.md) | Peer DHE parameters skip prime and generator validation | High |

### TLS 1.2 signature handling

| # | Finding | Severity |
|---|---------|----------|
| [003](003-tls-1-2-peer-sigalg-bypasses-security-level.md) | TLS 1.2 peer sigalg bypasses security level | Medium |
