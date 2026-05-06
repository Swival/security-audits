# OpenSSH Audit Findings

Security audit of OpenSSH, the portable SSH suite (client, server, agent, scp and sftp tools). Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 13** -- High: 5, Medium: 6, Low: 2

## Findings

### ssh-agent

| # | Finding | Severity |
|---|---------|----------|
| [001](001-malformed-lock-request-terminates-agent.md) | Malformed lock request terminates agent | Medium |

### Port forwarding and channels

| # | Finding | Severity |
|---|---------|----------|
| [002](002-streamlocal-remote-forwards-bypass-listen-acl-matching.md) | streamlocal remote forwards bypass listen ACL matching | High |

### scp and sftp

| # | Finding | Severity |
|---|---------|----------|
| [003](003-source-server-escapes-remote-target-directory.md) | Source server escapes remote target directory | High |
| [006](006-malicious-server-controls-local-download-destination.md) | Malicious server controls local download destination | Medium |
| [007](007-zero-length-read-data-causes-endless-download-loop.md) | Zero-length read data causes endless download loop | Medium |
| [008](008-zero-length-origin-data-causes-endless-crossload-loop.md) | Zero-length origin data causes endless crossload loop | Medium |
| [014](014-unbounded-remote-uid-name-cache.md) | Unbounded remote UID/GID name cache | Medium |

### Client authentication

| # | Finding | Severity |
|---|---------|----------|
| [004](004-certificate-private-key-match-dereferences-null-key.md) | Certificate private-key match dereferences null key | Medium |

### Cryptography

| # | Finding | Severity |
|---|---------|----------|
| [009](009-ec-subgroup-check-uses-zero-order.md) | EC subgroup check uses zero order | Low |
| [011](011-incremental-shake-256-skips-the-first-output-block.md) | Incremental SHAKE-256 skips the first output block | High |
| [012](012-ed25519-signatures-are-malleable-via-non-canonical-s.md) | Ed25519 accepts non-canonical S values | High |
| [013](013-ed25519-verifier-truncates-signed-message-length.md) | Ed25519 verifier truncates signed message length | Low |

### Build and supply chain

| # | Finding | Severity |
|---|---------|----------|
| [010](010-movable-upstream-ref-reaches-executed-check-binary.md) | Movable upstream ref reaches executed check binary | High |
