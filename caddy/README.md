# Caddy Audit Findings

Security audit of Caddy, a Go HTTP/2 and HTTP/3 web server with automatic HTTPS. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 8** -- High: 2, Medium: 6

## Findings

### Certificate management

| # | Finding | Severity |
|---|---------|----------|
| [011](011-explicit-managers-disable-on-demand-issuance-fail-closed.md) | Explicit managers disable on-demand issuance fail-closed | High |
| [013](013-non-200-success-permits-certificate-issuance.md) | Non-200 success permits certificate issuance | High |

### Reverse proxy

| # | Finding | Severity |
|---|---------|----------|
| [005](005-configured-tls-server-name-is-ignored.md) | Configured TLS server_name is ignored | Medium |

### Static files and request matching

| # | Finding | Severity |
|---|---------|----------|
| [004](004-escaped-path-exact-matcher-overmatches-suffixes.md) | Escaped path exact matcher overmatches suffixes | Medium |

### FastCGI

| # | Finding | Severity |
|---|---------|----------|
| [009](009-proxy-header-becomes-fastcgi-http-proxy.md) | Proxy header exported as FastCGI HTTP_PROXY | Medium |
| [020](020-oversized-fastcgi-parameter-key-panics-during-value-truncati.md) | Oversized FastCGI parameter key panics during value truncation | Medium |

### Authentication

| # | Finding | Severity |
|---|---------|----------|
| [010](010-basic-auth-cache-retains-attacker-password-material.md) | Basic auth cache retains attacker password material | Medium |

### Metrics

| # | Finding | Severity |
|---|---------|----------|
| [018](018-https-catch-all-hosts-bypass-metric-cardinality-protection.md) | HTTPS catch-all hosts bypass metric cardinality protection | Medium |
