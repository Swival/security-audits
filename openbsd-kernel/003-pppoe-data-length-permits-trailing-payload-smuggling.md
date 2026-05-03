# PPPoE data length permits trailing payload smuggling

## Classification

Policy bypass. Confidence: certain. Severity: medium.

## Affected Locations

`net/if_pppoe.c:760`

## Summary

`pppoe_data_input` trusted the PPPoE `plen` field only as a lower-bound length check. If an established PPPoE peer sent a data frame whose Ethernet payload was longer than the declared PPPoE payload, the function forwarded the full mbuf to `sppp_input`. This allowed trailing bytes outside the declared PPPoE payload to be interpreted by the PPP layer.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

An established PPPoE session receives attacker-sent data frames from the session peer.

## Proof

A malicious PPPoE session peer can send unicast `ETHERTYPE_PPPOE` code-0 traffic with the matching session id, `plen = 2`, and a longer actual PPP payload such as `PPP_LCP || LCP_TERM_REQ`.

Observed propagation:

- `pppoe_data_input` parses attacker-controlled `ph->plen` into `plen`.
- It strips only `PPPOE_HEADERLEN` with `m_adj`.
- It checks only `m->m_pkthdr.len < plen`.
- It does not reject or trim `m->m_pkthdr.len > plen`.
- It sets `ph_ifidx` and calls `sppp_input` with the full actual mbuf.

With `plen = 2`, the declared PPPoE payload contains only the PPP protocol discriminator, but the trailing LCP bytes remain in the mbuf. `sppp_input` dispatches those bytes, and an LCP Terminate-Request can be acted on, enabling trailing-byte smuggling with link teardown impact.

## Why This Is A Real Bug

The PPPoE length field defines the payload length that upper layers should receive. Accepting extra bytes violates that framing invariant.

The comparable fast path, `pppoe_vinput`, already enforces this invariant by trimming overlong payloads before delivering data upward:

```c
if (m->m_pkthdr.len > plen)
	m_adj(m, plen - m->m_pkthdr.len);
```

`pppoe_data_input` lacked the same enforcement, so two PPPoE receive paths handled overlong payloads inconsistently and one exposed undeclared trailing bytes to PPP processing.

## Fix Requirement

After removing the PPPoE header and validating that the mbuf contains at least `plen` bytes, the function must ensure the mbuf contains no more than `plen` bytes before calling `sppp_input`.

Acceptable fixes are:

- reject packets where `m->m_pkthdr.len > plen`; or
- trim the mbuf to exactly `plen`.

## Patch Rationale

The patch trims excess bytes with `m_adj(m, plen - m->m_pkthdr.len)` when the actual payload is longer than the declared PPPoE payload.

This matches the existing `pppoe_vinput` behavior, preserves valid packets, and prevents trailing undeclared bytes from reaching `sppp_input`.

## Residual Risk

None

## Patch

```diff
diff --git a/net/if_pppoe.c b/net/if_pppoe.c
index a5208d2..3ca78a5 100644
--- a/net/if_pppoe.c
+++ b/net/if_pppoe.c
@@ -905,6 +905,8 @@ pppoe_data_input(struct mbuf *m)
 
 	if (m->m_pkthdr.len < plen)
 		goto drop;
+	if (m->m_pkthdr.len > plen)
+		m_adj(m, plen - m->m_pkthdr.len);
 
 	/* fix incoming interface pointer (not the raw ethernet interface anymore) */
 	m->m_pkthdr.ph_ifidx = sc->sc_sppp.pp_if.if_index;
```