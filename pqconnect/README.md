# PQConnect Audit Findings

Security audit of PQConnect, a post-quantum VPN that authenticates and encrypts traffic between hosts using McEliece and X25519. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 4** -- High: 1, Medium: 3

## Findings

### Handshake and peer management

| # | Finding | Severity |
|---|---------|----------|
| [001](001-ephemeral-key-responses-ignore-udp-source.md) | Ephemeral key responses ignore UDP source | Medium |
| [002](002-unauthenticated-fail-packet-removes-active-peer.md) | Unauthenticated fail packet removes active peer | Medium |

### 0-RTT replay protection

| # | Finding | Severity |
|---|---------|----------|
| [003](003-timestamp-keyed-replay-cache-forgets-same-second-ciphertexts.md) | Timestamp-keyed replay cache forgets same-second ciphertexts | High |

### Cookie management

| # | Finding | Severity |
|---|---------|----------|
| [005](005-forged-cookie-checks-exhaust-epoch-nonce-counter.md) | Forged cookie checks exhaust epoch nonce counter | Medium |
