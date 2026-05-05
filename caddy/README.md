# Caddy Audit Findings

Security audit of Caddy, a Go HTTP/2 and HTTP/3 web server with automatic HTTPS. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 16** -- High: 4, Medium: 12

## Findings

### Certificate management

| # | Finding | Severity |
|---|---------|----------|
| [011](011-explicit-managers-disable-on-demand-issuance-fail-closed.md) | Explicit managers disable on-demand issuance fail-closed | High |
| [013](013-non-200-success-permits-certificate-issuance.md) | Non-200 success permits certificate issuance | High |
| [012](012-unbounded-certificate-endpoint-response-read.md) | Unbounded certificate endpoint response read | Medium |
| [019](019-short-stored-key-panics-certificate-loading.md) | Short stored key panics certificate loading | Medium |

### Reverse proxy

| # | Finding | Severity |
|---|---------|----------|
| [003](003-unbounded-health-check-body-read.md) | Unbounded health-check body read | Medium |
| [005](005-configured-tls-server-name-is-ignored.md) | Configured TLS server_name is ignored | Medium |

### Static files and request matching

| # | Finding | Severity |
|---|---------|----------|
| [001](001-hidden-precompressed-sidecar-can-be-served.md) | Hidden precompressed sidecar can be served | Medium |
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

### Admin and config adaptation

| # | Finding | Severity |
|---|---------|----------|
| [015](015-unbounded-adapt-request-body-buffering.md) | Unbounded adapt request body buffering | Medium |

### Metrics

| # | Finding | Severity |
|---|---------|----------|
| [018](018-https-catch-all-hosts-bypass-metric-cardinality-protection.md) | HTTPS catch-all hosts bypass metric cardinality protection | Medium |

### Repository workflows

| # | Finding | Severity |
|---|---------|----------|
| [006](006-unsigned-tag-name-executes-in-privileged-shell.md) | Unsigned tag name executes in privileged shell | High |
| [007](007-commit-subject-executes-in-github-script-template.md) | Commit subject executes in github-script template | High |
| [014](014-workflow-logs-maintainer-secret.md) | Workflow logs maintainer secret | Medium |
