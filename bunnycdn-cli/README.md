# BunnyCDN CLI Audit Findings

Security audit of the BunnyCDN command-line client. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 31** -- High: 0, Medium: 30, Low: 1

## Findings

### Templates and scripts

| # | Finding | Severity |
|---|---------|----------|
| [001](001-custom-template-auto-installs-dependencies.md) | Custom template auto-installs dependencies | Medium |

### Token and credential management

| # | Finding | Severity |
|---|---------|----------|
| [002](002-non-expiring-full-access-token-generation.md) | Non-expiring full-access token generation | Medium |
| [005](005-shell-auto-generates-permanent-full-access-token.md) | Shell auto-generates permanent full-access token | Medium |
| [007](007-generated-token-can-be-orphaned.md) | Generated token can be orphaned | Medium |
| [011](011-deployment-key-printed-in-cli-output.md) | Deployment key printed in CLI output | Medium |
| [014](014-force-removes-local-database-token-without-cleanup-confirmat.md) | Force delete removes local database token without cleanup confirmation | Medium |
| [017](017-token-remains-in-url-on-auth-failure.md) | Token remains in URL on auth failure | Medium |
| [019](019-json-config-output-exposes-api-key.md) | JSON config output exposes API key | Medium |

### Terminal output and logging

| # | Finding | Severity |
|---|---------|----------|
| [006](006-spinner-not-stopped-on-credential-fetch-failure.md) | Spinner not stopped on credential fetch failure | Low |
| [009](009-verbose-logging-exposes-request-bodies.md) | Verbose logging exposes request bodies | Medium |
| [010](010-verbose-logging-exposes-response-bodies.md) | Verbose logging exposes response bodies | Medium |
| [012](012-environment-value-echoed-to-terminal.md) | Environment value echoed to terminal | Medium |
| [020](020-unescaped-environment-value-injection.md) | Unescaped environment value injection | Medium |

### Local database server

| # | Finding | Severity |
|---|---------|----------|
| [015](015-unauthenticated-database-rest-server.md) | Unauthenticated database REST server | Medium |
| [016](016-unauthenticated-database-crud-handler.md) | Unauthenticated database CRUD handler | Medium |

### Database query handling

| # | Finding | Severity |
|---|---------|----------|
| [008](008-query-parameter-injection-via-column.md) | Query parameter injection via column | Medium |
| [029](029-filterless-update-affects-whole-table.md) | Filterless update affects whole table | Medium |
| [030](030-filterless-delete-affects-whole-table.md) | Filterless delete affects whole table | Medium |
| [031](031-unchecked-url-filters-reach-row-fetch.md) | Unchecked URL filters reach row fetch | Medium |
| [032](032-unchecked-url-sort-column-reaches-row-fetch.md) | Unchecked URL sort column reaches row fetch | Medium |
| [033](033-nonnumeric-limit-becomes-nan.md) | Nonnumeric limit becomes NaN | Medium |
| [034](034-nonnumeric-offset-becomes-nan.md) | Nonnumeric offset becomes NaN | Medium |

### Path traversal

| # | Finding | Severity |
|---|---------|----------|
| [021](021-path-traversal-in-saveview.md) | Path traversal in saveView | Medium |
| [022](022-path-traversal-in-loadview.md) | Path traversal in loadView | Medium |
| [023](023-path-traversal-in-deleteview.md) | Path traversal in deleteView | Medium |
| [027](027-path-traversal-in-manifest-write.md) | Path traversal in manifest write | Medium |
| [028](028-path-traversal-in-rooted-manifest-write.md) | Path traversal in rooted manifest write | Medium |

### Container deployment

| # | Finding | Severity |
|---|---------|----------|
| [013](013-patch-maps-first-container-to-wrong-id.md) | Patch maps first container to wrong ID | Medium |

### Output encoding

| # | Finding | Severity |
|---|---------|----------|
| [018](018-newline-injection-in-pulled-env-file.md) | Newline injection in pulled env file | Medium |
| [024](024-csv-formula-prefixes-preserved.md) | CSV formula prefixes preserved | Medium |
| [025](025-csv-escaping-omits-carriage-returns.md) | CSV escaping omits carriage returns | Medium |
