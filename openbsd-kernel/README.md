# OpenBSD Kernel Audit Findings

Security audit of the OpenBSD kernel: networking stack, packet filter, IPsec and WireGuard, PPP and tunnel drivers, System V IPC, pledge, suspend and hibernate, disklabel handling, and the syscall dispatch path. Each finding includes a detailed write-up and a patch.

## Summary

**Total findings: 33** -- High: 18, Medium: 15

## Findings

### PPP and PPPoE

| # | Finding | Severity |
|---|---------|----------|
| [001](001-pap-accepts-prefix-credentials.md) | PAP accepts prefix credentials | High |
| [002](002-forged-pads-establishes-session-before-padr.md) | Forged PADS establishes session before PADR | Medium |
| [003](003-pppoe-data-length-permits-trailing-payload-smuggling.md) | PPPoE data length permits trailing payload smuggling | Medium |
| [018](018-bsd-compress-accepts-impossible-next-code.md) | BSD-Compress accepts impossible next code | Medium |
| [026](026-deflate-output-ignores-negotiated-mru.md) | Deflate output ignores negotiated MRU | High |
| [037](037-variable-length-compressed-fields-read-past-packet-end.md) | Variable-length compressed fields read past packet end | High |
| [038](038-uncompressed-tcp-state-update-reads-unchecked-ip-header.md) | Uncompressed TCP state update reads unchecked IP header | High |

### Packet filter (pf)

| # | Finding | Severity |
|---|---------|----------|
| [009](009-fragment-cache-key-ignores-packet-direction.md) | Fragment cache key ignores packet direction | Medium |
| [020](020-non-cost-feedback-reads-cost-only-field.md) | Non-cost feedback reads cost-only field | Medium |
| [024](024-weighted-least-states-division-by-zero.md) | Weighted least-states division by zero | High |
| [033](033-vlan-tagged-traffic-bypasses-pf-filtering.md) | VLAN-tagged traffic bypasses PF filtering | Medium |
| [035](035-stale-fragment-counters-after-selective-discard.md) | Stale fragment counters after selective discard | Medium |

### IPsec and WireGuard

| # | Finding | Severity |
|---|---------|----------|
| [013](013-invalidated-wireguard-keypair-still-decrypts-data.md) | Invalidated WireGuard keypair still decrypts data | High |
| [014](014-esp-padding-verifier-checks-only-final-pad-byte.md) | ESP padding verifier checks only final pad byte | High |
| [023](023-unauthenticated-ah-packets-consume-sa-byte-lifetime.md) | Unauthenticated AH packets consume SA byte lifetime | Medium |
| [034](034-spd-dump-accepts-foreign-routing-table-without-privilege.md) | SPD dump accepts foreign routing table without privilege | Medium |

### IPv6 and multicast

| # | Finding | Severity |
|---|---------|----------|
| [004](004-zero-delay-mld-query-triggers-report-fanout.md) | Zero-delay MLD query triggers report fanout | Medium |
| [008](008-jumbo-packets-bypass-rh0-rejection.md) | Jumbo packets bypass RH0 rejection | High |

### Routing and sockets

| # | Finding | Severity |
|---|---------|----------|
| [025](025-default-rdomain-bypasses-so-rtable-privilege-check.md) | Default rdomain bypasses SO_RTABLE privilege check | Medium |
| [027](027-source-route-tag-deletion-uses-payload-pointer.md) | Source-route tag deletion uses payload pointer | High |

### tun and tap

| # | Finding | Severity |
|---|---------|----------|
| [012](012-enomem-path-leaks-tun-packet-mbufs.md) | ENOMEM path leaks tun packet mbufs | Medium |

### BPF

| # | Finding | Severity |
|---|---------|----------|
| [029](029-indirect-bpf-word-load-wraps-packet-offset.md) | Indirect BPF word load wraps packet offset | High |

### Suspend and hibernate

| # | Finding | Severity |
|---|---------|----------|
| [016](016-compressed-size-wrap-underallocates-pig-area.md) | Compressed size wrap underallocates pig area | High |
| [017](017-compressed-chunk-overruns-piglet-bounce-area.md) | Compressed chunk overruns piglet bounce area | High |

### Disklabel and disk drivers

| # | Finding | Severity |
|---|---------|----------|
| [005](005-disklabel-d-nsectors-zero-causes-diskerr-divide-by-zero.md) | Disklabel `d_nsectors` zero causes diskerr divide-by-zero | High |
| [015](015-disk-chunk-count-overruns-chunk-table-scan.md) | Disk chunk count overruns chunk table scan | Medium |

### Pledge

| # | Finding | Severity |
|---|---------|----------|
| [007](007-pledge-kill-allows-process-group-signaling.md) | Pledge kill allows process-group signaling | High |
| [022](022-pledge-open-fchflags-drops-unowned-vnode-reference.md) | Pledge-open fchflags drops unowned vnode reference | High |

### System V IPC

| # | Finding | Severity |
|---|---------|----------|
| [028](028-semaphore-wake-path-dereferences-freed-semid.md) | Semaphore wake path dereferences freed semid | High |
| [032](032-msgrcv-ignores-truncated-length-during-copyout.md) | msgrcv ignores truncated length during copyout | High |

### System calls and tracing

| # | Finding | Severity |
|---|---------|----------|
| [021](021-setitimer-ktrace-leaks-uninitialized-stack.md) | setitimer ktrace leaks uninitialized stack | Medium |
| [030](030-negative-syscall-number-reads-before-pins-array.md) | Negative syscall number reads before pins array | High |

### TTY

| # | Finding | Severity |
|---|---------|----------|
| [031](031-unprivileged-verauth-clear-ioctl.md) | Unprivileged verauth clear ioctl | Medium |
