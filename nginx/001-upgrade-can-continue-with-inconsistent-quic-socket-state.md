# Abort reload on partial QUIC BPF init failure

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `src/event/quic/ngx_event_quic_bpf.c:154`

## Summary
During reload-time QUIC BPF initialization, nginx can partially update QUIC socket/BPF state and then still return success on failure paths. This allows the upgrade to continue with inconsistent sockmap/program attachment state across listeners, risking misrouting of live QUIC packets.

## Provenance
- Verified finding reproduced from the provided report
- External scanner reference: https://swival.dev

## Preconditions
- A reload reaches QUIC BPF module initialization
- Some listener groups have already been updated
- A later QUIC BPF add/export step fails during that same reload

## Proof
`ngx_quic_bpf_module_init()` imports or duplicates existing map FDs, then iterates listeners and invokes QUIC BPF socket/group setup. Those setup steps can already mutate live state by attaching BPF programs, updating sockmaps, and marking listeners ignored. If a later step fails, the branch at `src/event/quic/ngx_event_quic_bpf.c:154` logs that state can be inconsistent and cannot be reverted, but on non-initial startup returns `NGX_OK`. This permits reload completion after partial mutation.

The reproduced impact shows why this matters:
- QUIC connection IDs encode the socket `SO_COOKIE` in `src/event/quic/ngx_event_quic_connid.c:54` and `src/event/quic/ngx_event_quic_connid.c:65`
- The BPF helper uses the first 8 bytes of DCID as the sockhash key in `src/event/quic/bpf/ngx_quic_reuseport_helper.c:112` and `src/event/quic/bpf/ngx_quic_reuseport_helper.c:114`
- If the socket is missing from the sockmap, lookup returns `-ENOENT` and the helper falls back to default reuseport selection in `src/event/quic/bpf/ngx_quic_reuseport_helper.c:122` and `src/event/quic/bpf/ngx_quic_reuseport_helper.c:124`
- A follow-up packet can then land on the wrong worker, fail QUIC connection lookup in `src/event/quic/ngx_event_quic_udp.c:369`, and trigger a stateless reset for unknown application packets in `src/event/quic/ngx_event_quic.c:880`

## Why This Is A Real Bug
This is not a harmless logging issue. The code explicitly acknowledges irreversible partial mutation, then treats that condition as success during reload. QUIC routing correctness depends on sockmap membership matching the encoded connection ID. Once those diverge, established flows can be delivered to the wrong worker and reset, causing real connection loss and protocol integrity failure during upgrade.

## Fix Requirement
On reload-time QUIC BPF initialization failure after any partial mutation, abort the reload instead of returning success. The process must fail closed so the new configuration is not activated with inconsistent QUIC socket state.

## Patch Rationale
The patch changes the non-initial failure path in `src/event/quic/ngx_event_quic_bpf.c` to return an error rather than `NGX_OK`. That aligns control flow with the already-documented irreversibility of the partial update and prevents nginx from committing a reload that can break active QUIC connections.

## Residual Risk
None

## Patch
Patch file: `001-upgrade-can-continue-with-inconsistent-quic-socket-state.patch`