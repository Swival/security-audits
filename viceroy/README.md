# Viceroy Audit Findings

Security audit of Viceroy, the local development server for Fastly Compute. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 30** -- High: 7, Medium: 23, Low: 0

## Findings

### Trap and error reporting

| # | Finding | Severity |
|---|---------|----------|
| [001](001-trap-details-returned-in-http-500-body.md) | Trap details exposed in HTTP 500 body | Medium |

### Cache hostcalls

| # | Finding | Severity |
|---|---------|----------|
| [002](002-duration-conversion-can-panic-on-large-cache-metadata.md) | Duration conversion panics on oversized cache metadata | Medium |
| [003](003-age-conversion-can-panic-on-large-cache-metadata.md) | Age conversion panics on oversized cache metadata | Medium |
| [004](004-get-body-leaks-a-spawned-body-stream-on-single-reader-reject.md) | get_body leaks a spawned stream when rejecting a second reader | Medium |
| [006](006-full-body-read-has-no-decompressed-size-limit.md) | Full-body read lacks a decoded size cap | Medium |

### KV and object store handles

| # | Finding | Severity |
|---|---------|----------|
| [008](008-invalid-pending-operation-handles-panic-on-await.md) | Invalid pending-operation handles panic on await | Medium |
| [010](010-invalid-store-handle-can-panic-hostcall.md) | Invalid store handle panics KV hostcalls | High |
| [011](011-lookup-wait-exposes-partial-state-on-buffer-error.md) | lookup_wait exposes partial state on buffer error | Medium |
| [017](017-invalid-store-handle-panics-host-lookup-paths.md) | Invalid store handle panics host lookup paths | High |
| [018](018-invalid-store-handle-panics-host-insert-paths.md) | Invalid store handle panics host insert paths | High |
| [019](019-invalid-store-handle-panics-host-delete-path.md) | Invalid store handle panics host delete path | High |

### Object store concurrency

| # | Finding | Severity |
|---|---------|----------|
| [012](012-insert-preconditions-race-concurrent-writers.md) | Insert preconditions race concurrent writers | High |
| [013](013-append-and-prepend-lose-concurrent-updates.md) | Append and prepend lose concurrent updates | High |

### HTTP and networking

| # | Finding | Severity |
|---|---------|----------|
| [014](014-invalid-pending-request-handle-panics-await-response.md) | Invalid pending request handle panics await_response | High |
| [015](015-get-header-values-panics-on-invalid-request-handle.md) | get_header_values panics on invalid request handle | Medium |
| [016](016-host-header-controls-backend-request-authority.md) | Host header overrides backend authority | Medium |
| [020](020-invalid-response-handle-traps-in-header-value-lookup.md) | Invalid response handle traps in header value lookup | Medium |
| [021](021-remote-ip-lookup-unwraps-untrusted-response-handle.md) | Remote IP lookup unwraps untrusted response handle | Medium |
| [022](022-remote-port-lookup-unwraps-untrusted-response-handle.md) | Remote port lookup unwraps untrusted response handle | Medium |
| [023](023-backend-name-injected-into-routing-header.md) | Backend route ID accepted without backend validation | Medium |

### Body and streaming

| # | Finding | Severity |
|---|---------|----------|
| [024](024-known-size-tee-panics-on-body-read-error.md) | Known-size tee panics on body read error | Medium |

### Header parsing

| # | Finding | Severity |
|---|---------|----------|
| [033](033-missing-trailing-nul-drops-last-header-value.md) | Missing trailing NUL drops last header value | Medium |
| [034](034-empty-values-buffer-clears-headers-silently.md) | Empty values buffer silently clears headers | Medium |

### Configuration parsing

| # | Finding | Severity |
|---|---------|----------|
| [026](026-empty-certificate-list-accepted-from-toml-sources.md) | Empty TOML client certificate chains bypass validation | Medium |
| [028](028-multiple-keys-in-file-or-inline-key-input-are-silently-accep.md) | Multiple PEM private keys are silently accepted | Medium |
| [030](030-missing-env-secret-becomes-empty-bytes.md) | Missing env secret becomes empty bytes | Medium |

### Shielding

| # | Finding | Severity |
|---|---------|----------|
| [029](029-oversized-shielding-backend-persists-after-length-error.md) | Oversized shielding backend persists after length error | Medium |

### Wasm module rewriting

| # | Finding | Severity |
|---|---------|----------|
| [039](039-valid-multi-memory-modules-panic-during-rewrite.md) | Valid multi-memory modules panic during rewrite | Medium |
| [040](040-large-memory-offsets-panic-on-checked-addition.md) | Large memarg offset overflow panics during rewrite | Medium |
| [041](041-supported-wasm-instructions-hit-todo-panic.md) | Supported Wasm instructions hit todo panic | Medium |
