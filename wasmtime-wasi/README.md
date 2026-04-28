# Wasmtime WASI Audit Findings

Security audit of the Wasmtime WASI implementation, covering the preview1 host interface, sockets, async streams, filesystem operations, and the Cranelift JIT memory provider. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 5** -- High: 2, Medium: 3

## Findings

### WASI preview1 (poll_oneoff / descriptors)

| # | Finding | Severity |
|---|---------|----------|
| [001](001-renumbering-leaks-replaced-descriptor-resource.md) | Renumbering leaks replaced descriptor resource | High |
| [002](002-absolute-realtime-timer-underflows-into-huge-sleep.md) | Absolute realtime timer underflows into huge sleep | High |

### WASI preview0

| # | Finding | Severity |
|---|---------|----------|
| [008](008-poll-oneoff-leaves-guest-subscriptions-corrupted-on-delegate.md) | poll_oneoff corrupts guest subscriptions on delegated error | Medium |

### Sockets

| # | Finding | Severity |
|---|---------|----------|
| [004](004-connect-cancellation-leaves-socket-in-connecting-state.md) | Connect cancellation strands socket in connecting state | Medium |

### Filesystem

| # | Finding | Severity |
|---|---------|----------|
| [009](009-append-fallback-races-on-shared-file-descriptions.md) | Append fallback races on shared file descriptions | Medium |
