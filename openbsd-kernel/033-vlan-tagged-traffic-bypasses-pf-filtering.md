# VLAN-tagged traffic bypasses PF filtering

## Classification

Policy bypass. Severity: medium. Confidence: certain.

## Affected Locations

`net/if_tpmr.c:281`

## Summary

`tpmr_pf()` returned VLAN-hardware-tagged mbufs without inspecting their EtherType or calling `pf_test()`. When `tpmr` allowed VLAN forwarding and PF was enabled, VLAN-tagged IP traffic could pass through `tpmr_input()` and be forwarded to the peer port without PF policy evaluation.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

## Preconditions

`tpmr` is running with PF enabled and VLAN forwarding allowed:

- PF path enabled for `tpmr`: `IFF_LINK1` unset.
- VLAN forwarding allowed: `IFF_LINK2` set.
- Attacker is an adjacent Ethernet host able to send VLAN-tagged Ethernet frames.

## Proof

The committed source confirms the bypass path:

- `tpmr_input()` only drops VLAN frames through `tpmr_vlan_filter()` when `IFF_LINK2` is unset.
- With `IFF_LINK2` set, VLAN-tagged frames continue into the forwarding path.
- With PF enabled, `tpmr_input()` calls `tpmr_pf()` for ingress and egress filtering.
- In `tpmr_pf()`, the `NVLAN` path returned any mbuf with `M_VLANTAG` immediately, before EtherType dispatch and before `pf_test()`.
- The non-NULL mbuf then continued through peer-port selection and was enqueued to the other physical port.

Impact: VLAN-tagged IP traffic could be forwarded without PF rules being applied, while equivalent untagged IP traffic would reach `pf_test()`.

## Why This Is A Real Bug

The `M_VLANTAG` early return was unconditional for VLAN-hardware-tagged packets. It did not distinguish non-IP frames from IPv4 or IPv6 frames, and it bypassed both the ingress and egress PF calls made by `tpmr_input()`. Because forwarding continues when `tpmr_pf()` returns the original mbuf, this creates a concrete firewall policy bypass for VLAN-tagged IP traffic.

## Fix Requirement

Do not return early solely because `M_VLANTAG` is set. VLAN-tagged IP packets must still be inspected for their inner EtherType and passed through `pf_test()` when PF filtering is enabled.

## Patch Rationale

The patch removes the `M_VLANTAG` early return in `tpmr_pf()`. After removal, tagged mbufs follow the same EtherType dispatch as untagged frames. IPv4 and IPv6 traffic reaches `pf_test()`, while unsupported EtherTypes still return unchanged through the existing default case.

## Residual Risk

None

## Patch

```diff
diff --git a/net/if_tpmr.c b/net/if_tpmr.c
index e96f561..577d326 100644
--- a/net/if_tpmr.c
+++ b/net/if_tpmr.c
@@ -278,11 +278,6 @@ tpmr_pf(struct ifnet *ifp0, int dir, struct mbuf *m, struct netstack *ns)
 	struct ether_header *eh, copy;
 	const struct tpmr_pf_ip_family *fam;
 
-#if NVLAN > 0
-	if (ISSET(m->m_flags, M_VLANTAG))
-		return (m);
-#endif
-
 	eh = mtod(m, struct ether_header *);
 	switch (ntohs(eh->ether_type)) {
 	case ETHERTYPE_IP:
```