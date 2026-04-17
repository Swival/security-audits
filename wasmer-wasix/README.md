# Wasmer WASIX Audit Findings

Security audit of Wasmer's WASIX implementation, covering the package manager and registry client, the virtual filesystem and I/O layer, networking and sockets, snapshot/restore and journaling, threading and scheduling, process management, and memory safety invariants. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 60** -- Critical: 1, High: 18, Medium: 41

## Findings

### Package management and registry

| # | Finding | Severity |
|---|---------|----------|
| [001](001-decompression-reads-unbounded-output-into-memory.md) | Decompression output cap added | Medium |
| [002](002-hash-verification-is-disabled-by-default.md) | Hash verification is disabled by default | Medium |
| [003](003-package-command-name-can-escape-bin-writes.md) | Package command names can escape intended `/bin` write targets | High |
| [007](007-graphql-query-injection-via-package-name-substitution.md) | GraphQL query injection via package name substitution | Medium |
| [008](008-cache-path-traversal-through-unsanitized-package-names.md) | Cache path traversal in cache key handling | High |
| [019](019-unchecked-sha-sidecar-overrides-real-package-hash.md) | Unchecked SHA sidecar overrides real package hash | Medium |
| [020](020-vendored-manifest-unwrap-can-fail-on-missing-wapm-fields.md) | Vendored manifest unwrap panics on partial `wapm` metadata | Medium |
| [024](024-engine-id-can-escape-cache-directory.md) | Engine ID path traversal in filesystem cache | Medium |
| [026](026-file-url-builder-fails-to-percent-encode-path-segments.md) | File URL path segments are not percent-encoded | Medium |
| [036](036-missing-dependency-alias-panics-during-filesystem-resolution.md) | Missing dependency alias panics during filesystem resolution | Medium |

### Filesystem and I/O

| # | Finding | Severity |
|---|---------|----------|
| [005](005-relative-library-paths-ignore-calling-module-directory.md) | Relative dependency paths bypass caller directory | High |
| [009](009-untrusted-file-read-can-panic-on-i-o-error.md) | Untrusted file read can panic on I/O error | Medium |
| [010](010-malformed-package-file-can-panic-during-package-creation.md) | Malformed package file panic on package creation | Medium |
| [011](011-write-lock-held-across-async-filesystem-load.md) | Write lock held across async filesystem load | Medium |
| [021](021-file-offset-advances-even-when-socket-send-writes-fewer-byte.md) | File offset skips unsent bytes on partial socket write | High |
| [022](022-eventnotifications-overreports-bytes-for-partial-u64-input.md) | EventNotifications partial writes misreport bytes written | Medium |
| [023](023-non-file-writes-corrupt-inode-size-metadata.md) | Non-file writes corrupt inode size metadata | Medium |
| [039](039-opened-fd-ignores-requested-base-rights.md) | Opened fd ignores requested base rights | Medium |
| [052](052-directory-rename-drops-source-entry-on-host-failure.md) | Directory rename leaves stale parent cache after host failure | High |
| [053](053-replacing-existing-target-leaves-stale-inode-metadata.md) | Rename replacement leaves stale inode metadata | High |
| [060](060-parent-entry-removed-before-unlink-succeeds.md) | Parent entry removed before unlink succeeds | High |
| [062](062-guest-path-reaches-filesystem-module-loader-unchecked.md) | Guest `dlopen` path bypasses guest file-access checks | Medium |
| [063](063-zero-length-error-buffer-underflows-truncation-length.md) | Zero-length error buffer underflows truncation length | Medium |
| [068](068-stderr-replay-buffered-into-stdout-sink.md) | Stderr replay buffered into stdout sink | High |
| [069](069-resolved-path-inode-not-updated.md) | Resolved path inode not updated | High |

### Networking and sockets

| # | Finding | Severity |
|---|---------|----------|
| [015](015-duplicate-spin-up-races-for-same-shard.md) | Duplicate shard spin-up race | Medium |
| [016](016-untrusted-x-shard-header-controls-backend-shard-selection.md) | Untrusted X-Shard header controls backend shard selection | Medium |
| [030](030-ipv6-segments-decoded-using-host-endianness.md) | IPv6 segment decoding depended on host endianness | Medium |
| [031](031-port-reader-mismatches-writer-byte-order.md) | Port reader mismatches writer byte order | High |
| [033](033-accepted-connections-are-tracked-without-any-concurrency-lim.md) | Accepted connection tracking lacks a concurrency bound | Medium |
| [057](057-unchecked-iovec-length-sum-can-wrap-max-size.md) | Unchecked iovec length sum can wrap max_size | Medium |
| [058](058-large-receives-ignore-dont-wait-request-flag.md) | Large receives ignore DONT_WAIT request flag | Medium |
| [064](064-socketpair-ignores-requested-family-and-type.md) | Socketpair ignores requested family and type | Medium |

### Snapshot, restore and journaling

| # | Finding | Severity |
|---|---------|----------|
| [038](038-replay-flag-cleared-before-restored-threads-start.md) | Replay flag cleared too early during snapshot restore | Medium |
| [043](043-bridge-token-persisted-to-journal.md) | Bridge token persisted to journal | Medium |
| [044](044-restore-grows-memory-using-wrong-base-offset.md) | Restore uses prior region end when sizing decompressed memory | High |
| [048](048-snapshot-prefix-validation-accepts-mismatched-stacks.md) | Snapshot prefix validation accepts mismatched stacks | Medium |
| [051](051-overwrites-active-checkpoint-state.md) | Overwrites active checkpoint state | Medium |
| [059](059-journal-replay-executes-arbitrary-filesystem-path-operations.md) | Journal replay replays forged root-scoped path operations | High |
| [065](065-snapshot-restore-writes-unchecked-globals-from-untrusted-des.md) | Snapshot restore accepts malformed global counts and crashes | Medium |

### Threading and scheduling

| # | Finding | Severity |
|---|---------|----------|
| [012](012-child-remains-registered-after-spawn-failure.md) | Child registration survives fork spawn failure | Medium |
| [027](027-task-manager-can-allocate-hundreds-of-dedicated-threads.md) | Task manager thread pool is oversized by default | Medium |
| [034](034-invalid-stack-globals-silently-collapse-to-zero-layout.md) | Invalid stack globals collapse stack base to zero | Medium |
| [035](035-terminate-marks-threads-finished-without-stopping-execution.md) | Terminate marks threads finished before they stop | High |
| [037](037-failed-deep-sleep-scheduling-leaves-thread-status-running.md) | Deep-sleep reschedule failure skips process teardown | Medium |
| [040](040-thread-spawn-panics-on-oversized-thread-id.md) | Thread spawn panics on oversized thread ID | Medium |
| [041](041-thread-spawn-panics-on-oversized-start-pointer.md) | Thread spawn panics on oversized start pointer | Medium |
| [045](045-task-limit-check-admits-one-extra-task.md) | Task limit check admits one extra task | High |
| [050](050-scheduler-errors-panic-in-async-helper.md) | Scheduler errors panic in async helper | Medium |
| [056](056-child-removed-before-successful-wait-completion.md) | Child removed before successful wait completion | Medium |

### Process and capability management

| # | Finding | Severity |
|---|---------|----------|
| [004](004-wasi-stderr-is-returned-verbatim-in-http-500.md) | WASI stderr exposed in HTTP 500 | Medium |
| [042](042-load-failure-panics-the-process.md) | Load failure panics the process | Medium |
| [049](049-wcgi-guest-gets-all-capabilities.md) | WCGI guest bypasses configured thread limits | Critical |
| [054](054-entrypoint-signature-check-accepts-one-sided-mismatches.md) | Entrypoint signature check accepts one-sided mismatches | High |
| [055](055-non-child-process-join-bypasses-parent-child-restriction.md) | Non-child `proc_join` bypasses parent-child restriction | High |
| [070](070-non-self-path-returns-target-pid-instead-of-parent-pid.md) | Non-self `proc_parent` returns target PID | Medium |

### Memory and type safety

| # | Finding | Severity |
|---|---------|----------|
| [013](013-reading-stack-offset-underflows-when-pointer-exceeds-stack-u.md) | Stack pointer bounds check underflow | Medium |
| [028](028-read-guard-marked-send-without-sync-bound.md) | Read guard `Send` without `Sync` bound | High |
| [029](029-write-guard-marked-send-without-required-sync-bound.md) | Write guard incorrectly marked `Send` | High |
| [067](067-empty-waiter-set-still-reports-wake.md) | Empty waiter set still reports wake | Medium |
