# DHCPDECLINE Can Abandon Another Client's Lease

## Classification

denial of service, medium severity

## Affected Locations

`usr.sbin/dhcpd/dhcp.c:504`

## Summary

An unauthenticated DHCP client on a served network can send a `DHCPDECLINE` containing `DHO_DHCP_REQUESTED_ADDRESS` for another client's lease. The server looks up that attacker-supplied address and abandons the matching lease without verifying that the sender owns it, making the target lease unavailable.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain

## Preconditions

An attacker can send `DHCPDECLINE` packets to a served DHCP network.

## Proof

`dhcpdecline()` accepts any `DHCPDECLINE` whose `DHO_DHCP_REQUESTED_ADDRESS` option length is 4. It copies the attacker-controlled requested address into `cip`, resolves it with `find_lease_by_ip_addr(cip)`, logs the sender hardware address, and then performs the state-changing operation:

```c
if (lease)
	abandon_lease(lease, "declined.");
```

There is no client identifier, hardware address, `ciaddr`, or other lease ownership comparison before `abandon_lease()` is called.

The reproducer confirmed:

- `usr.sbin/dhcpd/dhcp.c:491`, `usr.sbin/dhcpd/dhcp.c:495`, and `usr.sbin/dhcpd/dhcp.c:498` accept and resolve the attacker-supplied requested address.
- `usr.sbin/dhcpd/dhcp.c:506` and `usr.sbin/dhcpd/dhcp.c:514` allow the lease to be abandoned when not already in ACK/OFFER state.
- `usr.sbin/dhcpd/memory.c:666`, `usr.sbin/dhcpd/memory.c:672`, and `usr.sbin/dhcpd/memory.c:676` show `abandon_lease()` sets `ABANDONED_LEASE`, clears hardware address and UID, extends the lease end time, commits it, and moves it to purgatory.

Impact: any reachable DHCP client can name another client's active lease and force it into abandoned state, causing targeted lease unavailability and failed future matching or renewal until the abandoned period expires.

## Why This Is A Real Bug

The DHCP server treats `DHO_DHCP_REQUESTED_ADDRESS` in `DHCPDECLINE` as authority to mutate lease state. That option is fully client-controlled and is not bound to the sender. Existing lease ownership data already exists in the lease record through client identifier and hardware address fields, but `dhcpdecline()` did not use it before calling `abandon_lease()`.

This permits a practical targeted denial of service against another client's lease from an unauthenticated client on the served network.

## Fix Requirement

Before calling `abandon_lease()` for a `DHCPDECLINE`, verify that the sender owns the lease being declined. Ownership must match either:

- the DHCP client identifier, when the lease has a UID; or
- the hardware type, hardware length, and hardware address, when the lease has no UID.

If ownership does not match, the server must not abandon the lease.

## Patch Rationale

The patch adds the missing ownership check directly around the `abandon_lease()` call in `dhcpdecline()`.

The new condition only abandons the lease when:

- `lease->uid_len` is set and the packet includes an equal-length `DHO_DHCP_CLIENT_IDENTIFIER` matching `lease->uid`; or
- the lease has no UID and the packet hardware type, hardware length, and hardware address match the lease hardware address.

This mirrors the ownership logic already used elsewhere in DHCP request handling and prevents an attacker from naming an arbitrary lease by IP address alone.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/dhcpd/dhcp.c b/usr.sbin/dhcpd/dhcp.c
index 2380980..090bd0e 100644
--- a/usr.sbin/dhcpd/dhcp.c
+++ b/usr.sbin/dhcpd/dhcp.c
@@ -510,8 +510,17 @@ dhcpdecline(struct packet *packet)
 		return;
 	}
 
-	/* If we found a lease, mark it as unusable and complain. */
-	if (lease)
+	/* If we found a lease owned by this client, mark it as unusable. */
+	if (lease && ((lease->uid_len &&
+	    packet->options[DHO_DHCP_CLIENT_IDENTIFIER].data &&
+	    lease->uid_len ==
+	    packet->options[DHO_DHCP_CLIENT_IDENTIFIER].len &&
+	    !memcmp(packet->options[DHO_DHCP_CLIENT_IDENTIFIER].data,
+	    lease->uid, lease->uid_len)) || (!lease->uid_len &&
+	    lease->hardware_addr.htype == packet->raw->htype &&
+	    lease->hardware_addr.hlen == packet->raw->hlen &&
+	    !memcmp(lease->hardware_addr.haddr, packet->raw->chaddr,
+	    lease->hardware_addr.hlen))))
 		abandon_lease(lease, "declined.");
 }
```