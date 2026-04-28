# BunnyCDN Token Authentication Audit Findings

Security audit of the BunnyCDN token authentication libraries across all supported language implementations. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 8** -- High: 3, Medium: 5

## Findings

### Rust

| # | Finding | Severity |
|---|---------|----------|
| [001](001-signed-url-drops-explicit-port-and-userinfo.md) | Signed URL drops explicit port and userinfo | Medium |

### C#

| # | Finding | Severity |
|---|---------|----------|
| [003](003-duplicate-query-keys-crash-signing.md) | Duplicate query keys crash signing | Medium |

### Java

| # | Finding | Severity |
|---|---------|----------|
| [005](005-signed-url-drops-non-default-port-and-user-info.md) | Signed URL drops non-default port and user info | High |
| [006](006-duplicate-query-keys-are-rejected-instead-of-preserved.md) | Duplicate query keys block ignore-params signing | Medium |

### Node.js

| # | Finding | Severity |
|---|---------|----------|
| [007](007-signed-token-can-be-removed-from-output-url.md) | Signed token can be removed from output URL | High |
| [008](008-duplicate-reserved-params-in-directory-urls.md) | Duplicate reserved params in directory URLs | Medium |

### PHP

| # | Finding | Severity |
|---|---------|----------|
| [009](009-malformed-urls-become-signed-host-only-urls.md) | Malformed URLs are signed instead of rejected | High |
| [010](010-port-and-userinfo-are-dropped-from-returned-url.md) | Preserve authority components when rebuilding signed URLs | Medium |
