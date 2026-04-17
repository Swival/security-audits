# wasm-tools wasmparser Audit Findings

Security audit of the wasmparser crate from the wasm-tools project, covering binary module parsing and relocation validation. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 2** -- Medium: 2

## Findings

### Relocation validation

| # | Finding | Severity |
|---|---------|----------|
| [001](001-relocation-range-end-can-wrap-on-32-bit-targets.md) | Relocation range end can wrap on 32-bit targets | Medium |

### Memory type parsing

| # | Finding | Severity |
|---|---------|----------|
| [002](002-memory-width-decoded-from-reader-state-not-flags.md) | Memory width decoded from reader state, not flags | Medium |
