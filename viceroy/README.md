# Viceroy Audit Findings

Security audit of Viceroy, Fastly's local development server for Compute@Edge. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 30** -- High: 7, Medium: 23, Low: 0

## Findings

### Caching

| # | Finding | Severity |
|---|---------|----------|
| [002](002-duration-conversion-can-panic-on-large-cache-metadata.md) | Duration conversion can panic on large cache metadata | Medium |
| [003](003-age-conversion-can-panic-on-large-cache-metadata.md) | Age conversion can panic on large cache metadata | Medium |

### Object store

| # | Finding | Severity |
|---|---------|----------|
| [008](008-invalid-pending-operation-handles-panic-on-await.md) | Invalid pending operation handles panic on await | Medium |
| [010](010-invalid-store-handle-can-panic-hostcall.md) | Invalid store handle can panic hostcall | High |
| [011](011-lookup-wait-exposes-partial-state-on-buffer-error.md) | Lookup wait exposes partial state on buffer error | Medium |
| [012](012-insert-preconditions-race-concurrent-writers.md) | Insert preconditions race concurrent writers | High |
| [013](013-append-and-prepend-lose-concurrent-updates.md) | Append and prepend lose concurrent updates | High |
| [017](017-invalid-store-handle-panics-host-lookup-paths.md) | Invalid store handle panics host lookup paths | High |
| [018](018-invalid-store-handle-panics-host-insert-paths.md) | Invalid store handle panics host insert paths | High |
| [019](019-invalid-store-handle-panics-host-delete-path.md) | Invalid store handle panics host delete path | High |

### HTTP handling

| # | Finding | Severity |
|---|---------|----------|
| [001](001-trap-details-returned-in-http-500-body.md) | Trap details returned in HTTP 500 body | Medium |
| [014](014-invalid-pending-request-handle-panics-await-response.md) | Invalid pending request handle panics await response | High |
| [015](015-get-header-values-panics-on-invalid-request-handle.md) | get_header_values panics on invalid request handle | Medium |
| [016](016-host-header-controls-backend-request-authority.md) | Host header controls backend request authority | Medium |
| [020](020-invalid-response-handle-traps-in-header-value-lookup.md) | Invalid response handle traps in header value lookup | Medium |
| [021](021-remote-ip-lookup-unwraps-untrusted-response-handle.md) | Remote IP lookup unwraps untrusted response handle | Medium |
| [022](022-remote-port-lookup-unwraps-untrusted-response-handle.md) | Remote port lookup unwraps untrusted response handle | Medium |
| [023](023-backend-name-injected-into-routing-header.md) | Backend name injected into routing header | Medium |

### Body handling

| # | Finding | Severity |
|---|---------|----------|
| [004](004-get-body-leaks-a-spawned-body-stream-on-single-reader-reject.md) | get_body leaks a spawned body stream on single reader reject | Medium |
| [006](006-full-body-read-has-no-decompressed-size-limit.md) | Full body read has no decompressed size limit | Medium |
| [024](024-known-size-tee-panics-on-body-read-error.md) | Known-size tee panics on body read error | Medium |

### Configuration

| # | Finding | Severity |
|---|---------|----------|
| [026](026-empty-certificate-list-accepted-from-toml-sources.md) | Empty certificate list accepted from TOML sources | Medium |
| [028](028-multiple-keys-in-file-or-inline-key-input-are-silently-accep.md) | Multiple keys in file or inline key input are silently accepted | Medium |
| [029](029-oversized-shielding-backend-persists-after-length-error.md) | Oversized shielding backend persists after length error | Medium |
| [030](030-missing-env-secret-becomes-empty-bytes.md) | Missing env secret becomes empty bytes | Medium |

### Header handling

| # | Finding | Severity |
|---|---------|----------|
| [033](033-missing-trailing-nul-drops-last-header-value.md) | Missing trailing NUL drops last header value | Medium |
| [034](034-empty-values-buffer-clears-headers-silently.md) | Empty values buffer clears headers silently | Medium |

### WebAssembly module handling

| # | Finding | Severity |
|---|---------|----------|
| [039](039-valid-multi-memory-modules-panic-during-rewrite.md) | Valid multi-memory modules panic during rewrite | Medium |
| [040](040-large-memory-offsets-panic-on-checked-addition.md) | Large memory offsets panic on checked addition | Medium |
| [041](041-supported-wasm-instructions-hit-todo-panic.md) | Supported wasm instructions hit todo panic | Medium |
