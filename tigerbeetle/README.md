# TigerBeetle Audit Findings

Security audit of [TigerBeetle](https://tigerbeetle.com/), a financial transactions database designed for mission-critical safety and performance. Each finding includes a detailed write-up and a patch.

The original automated report was reviewed by hand against the repository's actual threat model and coding style (`docs/TIGER_STYLE.md`). Three of the originally surfaced findings were dropped as false positives or as disputes with intentional design choices; the remaining ten have been re-graded and their write-ups annotated with the corresponding threat-model context.

## Summary

**Total findings: 10** -- Medium: 3, Low: 7

Three additional reports were investigated and discarded:

- An alleged PID 1 sandbox bypass in `src/stdx/unshare.zig` — the PID-1 path is reached only by the re-exec'd inner child of a previous `unshare`, which has already inherited the parent's network namespace and loopback setup. The proposed patch would actively break the design.
- Two reports of "unknown VSR command crashes the replica" (`message_buffer.zig` and `message_header.zig`) — the crash is deliberate, exposed as `FatalReason.unknown_vsr_command` and documented as "crashing for safety". This is a design choice, not a bug.

## Findings

### Build and release tooling

| # | Finding | Severity |
|---|---------|----------|
| [001](001-devhub-pat-exposed-in-git-clone-argv.md) | devhub PAT exposed in `git clone` argv | Low |
| [002](002-unchecked-mach-o-slice-bounds-abort-build.md) | Unchecked Mach-O slice bounds abort the multiversion build | Low |

### AMQP CDC client

| # | Finding | Severity |
|---|---------|----------|
| [003](003-oversized-amqp-frame-panics-receive-buffering.md) | Oversized AMQP frame trips a receive-buffer assertion | Low |
| [004](004-unknown-amqp-method-traps-client-decoder.md) | Unknown AMQP method traps the client decoder | Low |
| [014](014-unsupported-amqp-field-tag-terminates-process.md) | Unsupported AMQP field tag terminates the process | Low |
| [015](015-unknown-amqp-method-header-aborts-client-decoding.md) | Generator-side counterpart of finding 004 (fixes `spec_parser.py`) | Low |

### Node native client

| # | Finding | Severity |
|---|---------|----------|
| [007](007-deinit-leaves-external-client-dangling.md) | `deinit` leaves the JavaScript external pointing at freed memory | Medium |

### VSR, message bus, and storage

| # | Finding | Severity |
|---|---------|----------|
| [008](008-malformed-wal-prepare-size-crashes-inspect.md) | Malformed WAL prepare size crashes `tigerbeetle inspect` | Low |
| [010](010-idle-accepted-sockets-exhaust-all-connection-slots.md) | Idle accepted sockets exhaust the connection slot pool | Medium |
| [013](013-oversized-trailer-reference-writes-past-block-arrays.md) | Oversized checkpoint trailer reference writes past block arrays | Medium |

## Notes on the AMQP cluster

Findings 003, 004, 014, and 015 all live on the CDC AMQP receive path. The broker is part of the operator-configured topology rather than an arbitrary network attacker, and the receive loop in `src/cdc/amqp.zig` already calls `fatal()` on any `Decoder.Error.Unexpected`. So in their patched form these findings primarily replace ad-hoc traps (assertion trips, `@enumFromInt` on attacker-controlled bytes, deep `fatal` calls in table decoding) with a single well-defined error path that routes through the established decoder-error channel. The DoS outcome (process exit) is largely the same in patched and unpatched code; what changes is attributability, error-message quality, and the ability to later move to reconnect-on-protocol-error without further refactoring.
