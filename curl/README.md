# curl Audit Findings

Security audit of curl, the command-line tool and `libcurl` library for transferring data over many protocols. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 17** -- High: 6, Medium: 9, Low: 2

## Findings

### TLS trust store and public key pinning

| # | Finding | Severity |
|---|---------|----------|
| [001](001-searchpath-ca-bundle-lookup-trusts-attacker-writable-directo.md) | SearchPath CA bundle lookup trusts attacker-writable directories | High |
| [004](004-cached-ca-store-overrides-ssl-context-callback.md) | Cached CA store overrides SSL context callback | High |
| [016](016-unsupported-origin-public-key-pinning-fails-open.md) | Unsupported origin public key pinning fails open | High |
| [017](017-unsupported-proxy-public-key-pinning-fails-open.md) | Unsupported proxy public key pinning fails open | High |

### SSH

| # | Finding | Severity |
|---|---------|----------|
| [003](003-missing-knownhosts-skips-ssh-host-key-verification.md) | Missing knownhosts skips SSH host key verification | High |

### Authentication and credential handling

| # | Finding | Severity |
|---|---------|----------|
| [009](009-unauthenticated-ldap-url-uses-ambient-windows-credentials.md) | Unauthenticated LDAP URL uses ambient Windows credentials | High |
| [014](014-negotiate-auth-error-is-treated-as-success.md) | Negotiate auth error is treated as success | Medium |
| [008](008-sspi-decrypted-data-buffer-is-freed-with-wrong-allocator.md) | SSPI decrypted data buffer is freed with wrong allocator | Medium |

### SOCKS5

| # | Finding | Severity |
|---|---------|----------|
| [007](007-socks5-gssapi-protection-negotiation-is-ignored.md) | SOCKS5 GSSAPI protection negotiation is ignored | Medium |

### FTP and TFTP

| # | Finding | Severity |
|---|---------|----------|
| [005](005-active-ftp-accepts-first-inbound-peer.md) | Active FTP accepts first inbound peer | Medium |
| [011](011-first-tftp-response-pins-spoofed-peer-address.md) | First TFTP response pins spoofed peer address | Medium |

### HTTP transfer coding

| # | Finding | Severity |
|---|---------|----------|
| [013](013-duplicate-chunked-stops-transfer-coding-parsing.md) | Duplicate chunked stops transfer coding parsing | Medium |
| [012](012-identity-prefix-accepted-as-identity-transfer-coding.md) | Identity prefix accepted as identity transfer coding | Low |

### HTTP/2

| # | Finding | Severity |
|---|---------|----------|
| [006](006-goaway-last-stream-id-ignored-aborts-tunnel.md) | GOAWAY last_stream_id ignored aborts tunnel | Medium |

### Telnet

| # | Finding | Severity |
|---|---------|----------|
| [010](010-telnet-upload-blocks-past-configured-timeout.md) | Telnet upload blocks past configured timeout | Medium |

### Random number generation

| # | Finding | Severity |
|---|---------|----------|
| [015](015-windows-random-truncates-large-length-requests.md) | Windows random truncates large length requests | Low |

### Command-line tool

| # | Finding | Severity |
|---|---------|----------|
| [002](002-unauthenticated-loopback-stdin-bridge-exposes-stdin.md) | Unauthenticated loopback stdin bridge exposes stdin | Medium |
