# Multicast Path Sends Plaintext After MPPE Encryption

## Classification

High severity policy bypass.

## Affected Locations

`usr.sbin/npppd/npppd/npppd_iface.c:426`

## Summary

The non-pppx IPv4 multicast forwarding path sends multicast packets to every matching PPP session. When MPPE is active, the multicast delegate encrypts the packet with `mppe_pkt_output()`, but then falls through and also sends the original packet with `ppp_output(... PPP_PROTO_IP ...)`. This injects plaintext IPv4 packets into MPPE-protected PPP sessions, bypassing the configured encryption policy.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The npppd interface is a non-pppx interface.
- One or more PPP sessions on that interface have MPPE send state ready.
- An attacker-controlled IPv4 multicast packet is delivered to the npppd interface.

## Proof

For non-pppx interfaces, `npppd_iface_network_input_ipv4()` detects IPv4 multicast destinations with `IN_MULTICAST(ntohl(iphdr->ip_dst.s_addr))` and delegates delivery to all PPP sessions using `rd_walktree()`.

In `npppd_iface_network_input_delegate()`:

- `MPPE_SEND_READY(ppp)` being true calls `mppe_pkt_output(&ppp->mppe, PPP_PROTO_IP, args->pktp, args->lpktp)`.
- Execution then continues past the MPPE block.
- The same original packet is sent with `ppp_output(ppp, PPP_PROTO_IP, 0, 0, args->pktp, args->lpktp)`.

The reproduced control-flow comparison confirms the unicast path already has the intended guard: after `mppe_pkt_output()` it immediately returns, preventing plaintext fall-through.

## Why This Is A Real Bug

MPPE-ready sessions require outgoing IP payloads to be protected by MPPE. The multicast path violates that invariant by sending two copies of the same attacker-controlled packet:

- an encrypted MPPE frame via `mppe_pkt_output()`
- a plaintext `PPP_PROTO_IP` frame via `ppp_output()`

`mppe_pkt_output()` emits an MPPE frame, while `ppp_output()` only frames and sends the supplied protocol payload; it does not apply MPPE itself. Therefore the fall-through sends plaintext data into a session that should receive only MPPE-protected traffic.

## Fix Requirement

Return immediately after `mppe_pkt_output()` in the multicast delegate so MPPE-ready PPP sessions receive only the encrypted MPPE frame.

## Patch Rationale

The patch adds `return 0;` after the MPPE output call in `npppd_iface_network_input_delegate()`. This matches the existing unicast behavior in `npppd_iface_network_input_ipv4()`, where MPPE output is terminal and plaintext `ppp_output()` is skipped.

The change preserves existing behavior for:

- non-MPPE sessions, which still use `ppp_output()`
- MPPE-required but not ready sessions, which are still dropped
- tree walking, because returning `0` continues `rd_walktree()` iteration while stopping processing for the current PPP session

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/npppd/npppd/npppd_iface.c b/usr.sbin/npppd/npppd/npppd_iface.c
index 103520f..af1638f 100644
--- a/usr.sbin/npppd/npppd/npppd_iface.c
+++ b/usr.sbin/npppd/npppd/npppd_iface.c
@@ -418,6 +418,7 @@ npppd_iface_network_input_delegate(struct radish *radish, void *args0)
 			/* output via MPPE if MPPE started */
 			mppe_pkt_output(&ppp->mppe, PPP_PROTO_IP, args->pktp,
 			    args->lpktp);
+			return 0;
 		} else if (MPPE_IS_REQUIRED(ppp)) {
 			/* in case MPPE not started but MPPE is mandatory, */
 			/* it is not necessary to log because of multicast. */
```