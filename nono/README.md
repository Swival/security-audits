# nono Audit Findings

Security audit of [nono](https://github.com/jedisct1/nono), a Rust sandbox and supervisor for running untrusted code and AI-agent workflows under per-capability approval, with Landlock and seccomp on Linux and equivalent controls on macOS. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 38** -- High: 19, Medium: 16, Low: 3

## Findings

### Sandbox and OS-level isolation

| # | Finding | Severity |
|---|---------|----------|
| [001](001-procfs-parent-traversal-bypasses-procfs-access-filter.md) | procfs parent traversal bypasses the procfs access filter | High |
| [002](002-exact-landlock-deny-overlap-is-accepted.md) | Exact Landlock deny-overlap is accepted | High |
| [004](004-procfs-self-grant-widens-to-all-procfs.md) | procfs self grant widens to all of procfs | Low |
| [005](005-proxy-seccomp-fallback-allows-untrapped-udp-egress.md) | Proxy seccomp fallback allows untrapped UDP egress | High |
| [006](006-mutable-sockaddr-authorization-races-continued-syscall.md) | Mutable sockaddr authorization races the continued syscall | High |
| [009](009-home-spoof-disables-keychain-sandbox-denies.md) | HOME-derived keychain check can be spoofed when env is untrusted | Low |
| [010](010-localhost-port-grants-allow-arbitrary-inbound-tcp.md) | Localhost-port grants emit blanket inbound TCP on macOS | Medium |
| [016](016-child-raced-sockaddr-bypasses-network-sandbox.md) | Child-raced sockaddr bypasses the network sandbox | High |
| [027](027-sandbox-guard-trusts-removable-environment-variable.md) | Sandbox guard trusts a removable environment variable | High |

### Supervisor, approval, and credential handling

| # | Finding | Severity |
|---|---------|----------|
| [003](003-temp-path-shell-injection-in-sudo-fs-usage-wrapper.md) | Temp-path shell injection in the sudo `fs_usage` wrapper | High |
| [015](015-rust-dev-exposes-cargo-credential-store.md) | `rust-dev` exposes the Cargo credential store | High |
| [018](018-filesystem-supervisor-socket-accepts-unauthenticated-peer.md) | Filesystem supervisor socket accepts an unauthenticated peer | Medium |
| [031](031-bidi-controls-spoof-approval-prompt-paths.md) | Bidi controls spoof approval-prompt paths | Medium |

### CONNECT proxy and HTTP receive path

| # | Finding | Severity |
|---|---------|----------|
| [007](007-unbounded-request-line-read-exhausts-proxy-memory.md) | Unbounded request-line read exhausts proxy memory | Medium |
| [017](017-split-status-line-falsifies-response-audit.md) | Split status line falsifies the response audit log | Medium |
| [021](021-unbounded-sni-certificate-cache.md) | Unbounded SNI certificate cache | Medium |
| [024](024-connect-proxy-authorization-fails-open.md) | CONNECT proxy authorization fails open | Medium |
| [025](025-unbounded-inner-header-line-allocation.md) | Unbounded inner header-line allocation | Medium |

### Endpoint policy, signing, and trust

| # | Finding | Severity |
|---|---------|----------|
| [008](008-endpoint-segment-wildcard-spans-multiple-path-segments.md) | Endpoint segment wildcard spans multiple path segments | High |
| [012](012-unsigned-project-policy-can-define-trusted-publishers.md) | Unsigned project policy can define trusted publishers | High |
| [020](020-unsigned-project-policy-disables-pre-exec-trust-scanning.md) | Unsigned project policy disables pre-exec trust scanning | High |
| [028](028-keyed-dsse-verifier-ignores-payloadtype.md) | Keyed DSSE verifier ignores `payloadType` | High |
| [033](033-signed-audit-command-is-not-verified.md) | Signed `audit` command is not verified | High |
| [034](034-project-policy-can-add-trusted-publishers.md) | Project policy can add trusted publishers | High |
| [038](038-lockfile-registry-overrides-official-pack-status-authority.md) | Lockfile registry overrides official-pack status authority | High |
| [039](039-status-fetch-errors-bypass-yanked-pack-block.md) | Status-fetch errors bypass the yanked-pack block | Medium |

### Workflow dispatch and external builds

| # | Finding | Severity |
|---|---------|----------|
| [011](011-external-tag-build-runs-with-write-token.md) | External tag build runs with a write-scoped token | High |
| [019](019-dispatch-version-executes-shell-commands-in-privileged-workf.md) | Dispatch `version` executes shell commands in a privileged workflow | Medium |
| [022](022-repository-dispatch-version-enables-workflow-command-executi.md) | `repository_dispatch` version enables workflow-command execution | Medium |
| [023](023-repository-dispatch-version-injects-shell-commands.md) | `repository_dispatch` version injects shell commands | Medium |

### Pack install, snapshots, and undo tracking

| # | Finding | Severity |
|---|---------|----------|
| [014](014-unowned-symlinks-are-silently-repointed.md) | Unowned symlinks are silently repointed | High |
| [029](029-restore-parent-symlink-race-escapes-tracked-root.md) | Restore parent symlink race escapes the tracked root | Medium |
| [030](030-stale-walk-path-permits-outside-root-deletion.md) | Stale walk path permits outside-root deletion | Medium |
| [035](035-verified-file-protection-omits-unlink-and-rename-denial.md) | Verified-file protection omits unlink and rename denial | High |
| [036](036-filesystem-state-reload-ignores-canonical-path.md) | Filesystem-state reload ignores the canonical path | Medium |
| [037](037-merkle-snapshot-commitment-omits-permissions.md) | Merkle snapshot commitment omits file permissions | High |

### Logging and terminal output

| # | Finding | Severity |
|---|---------|----------|
| [026](026-audit-path-terminal-escape-injection.md) | Audit path terminal-escape injection | Medium |
| [032](032-claude-api-key-prefix-written-to-attacker-readable-temp-log.md) | Claude API key prefix written to an attacker-readable temp log | Low |
