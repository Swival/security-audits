# Multicast ARP Sender MAC Is Accepted Into Cache

## Classification

Cache poisoning, medium severity, confidence certain.

## Affected Locations

`netinet/if_ether.c:619`

## Summary

`in_arpinput()` attempts to reject invalid ARP sender hardware addresses, but uses logical AND between multicast and broadcast checks. Because Ethernet broadcast is a subset of multicast, a non-broadcast multicast `arp_sha` bypasses the check and can be cached as the link-layer address for a unicast IPv4 peer.

## Provenance

Verified by reproduction from the supplied finding and source analysis. Initial report attributed to Swival Security Scanner: https://swival.dev

## Preconditions

The victim has, or can be induced to create, an ARP cache entry for the sender protocol address.

## Proof

An adjacent network attacker sends an ARP request or reply with:

- A valid unicast outer Ethernet source address.
- `arp_spa` set to the peer IPv4 address to poison.
- `arp_sha` set to an attacker-chosen multicast MAC address that is not the all-ones broadcast address.
- For entry creation, `arp_tpa` set to a local victim IPv4 address so `target = 1`.

The vulnerable path is:

- `in_arpinput()` reads `ea->arp_sha` from the received ARP packet.
- The invalid-address filter uses `ETHER_IS_MULTICAST(ea->arp_sha) && ETHER_IS_BROADCAST(ea->arp_sha)`.
- A multicast-but-not-broadcast address makes the expression false and is accepted.
- `arplookup(&isaddr, target, 0, rdomain)` obtains or creates the ARP cache entry.
- `arpcache(ifp, ea, rt)` copies `ea->arp_sha` into `LLADDR(sdl)`.
- Later IPv4 output through `arpresolve()` copies the cached link-layer address into the Ethernet destination without rejecting multicast or broadcast cache values.

Concrete impact: the victim’s ARP cache maps a unicast peer IP to an attacker-chosen multicast MAC, causing subsequent traffic for that peer to be emitted to the multicast L2 address instead of the peer’s unicast MAC.

## Why This Is A Real Bug

ARP sender hardware addresses represent the sender’s link-layer address for a protocol address. For Ethernet ARP cache resolution of a unicast IPv4 peer, accepting a multicast MAC is invalid and permits cache poisoning.

The code intended to reject multicast and broadcast sender hardware addresses, but the logical operator only rejects addresses that are both multicast and broadcast. This excludes ordinary multicast MAC addresses from rejection. The reproduced flow shows the unchecked value is installed in the ARP cache and later used for packet transmission.

## Fix Requirement

Reject ARP packets whose sender hardware address is multicast or broadcast.

## Patch Rationale

Changing the condition from logical AND to logical OR makes the validation match the intended policy:

- Reject multicast sender hardware addresses.
- Reject broadcast sender hardware addresses.
- Prevent non-broadcast multicast MACs from reaching `arpcache()`.

Because broadcast is also multicast on Ethernet, the OR form is conservative and correct. The existing logging and drop path remain unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/netinet/if_ether.c b/netinet/if_ether.c
index 653499a..55f4a49 100644
--- a/netinet/if_ether.c
+++ b/netinet/if_ether.c
@@ -616,7 +616,7 @@ in_arpinput(struct ifnet *ifp, struct mbuf *m)
 	sin.sin_len = sizeof(sin);
 	sin.sin_family = AF_INET;
 
-	if (ETHER_IS_MULTICAST(ea->arp_sha) &&
+	if (ETHER_IS_MULTICAST(ea->arp_sha) ||
 	    ETHER_IS_BROADCAST(ea->arp_sha)) {
 		inet_ntop(AF_INET, &isaddr, addr, sizeof(addr));
 		log(LOG_ERR, "arp: ether address is broadcast for IP address "
```