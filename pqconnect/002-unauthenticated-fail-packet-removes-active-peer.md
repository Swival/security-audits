# Unauthenticated fail packet removes active peer

## Classification

Denial of service, medium severity.

## Affected Locations

`src/pqconnect/tundevice.py:400`

## Summary

`TunDevice._queue_incoming()` accepted a bare `HANDSHAKE_FAIL` UDP datagram as authoritative based only on the sender IP address. If the source IP matched an established peer in `_ext2peer`, the code called `peer.error()` and `remove_peer(peer)`, removing active tunnel mappings and closing the peer.

The patch requires the fail packet source port to match `peer.get_pqcport()` before removing the peer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A peer is established or in `NEW` state.
- The attacker can send UDP traffic to the tunnel socket.
- The attacker’s observed source IP matches the peer’s external IP, for example another host behind the same NAT/public IP.
- The attacker does not need the peer’s tunnel keys or the peer’s expected source port in the vulnerable version.

## Proof

The vulnerable path is in `_queue_incoming()`:

- `recvfrom()` receives arbitrary UDP data and source address.
- If `pkt == HANDSHAKE_FAIL`, the code checks only `addr[0] in self._ext2peer`.
- It retrieves the peer by external IP only.
- If the peer state is `ESTABLISHED` or `NEW`, it calls `peer.error()` and `self.remove_peer(peer)`.

Reproduction confirmed that a peer established for `203.0.113.10` was removed when a UDP datagram with payload `b"\x03\x00"` was received from `("203.0.113.10", 44444)`.

Impact of removal is concrete:

- `remove_peer()` deletes the tunnel ID mapping in `_tid2peer`.
- `remove_peer()` deletes the internal route mapping in `_int2peer`.
- `remove_peer()` deletes the external IP mapping in `_ext2peer`.
- `remove_peer()` closes the peer.

After removal, inbound tunnel packets no longer resolve by tunnel ID, and outbound packets no longer resolve by internal peer IP.

## Why This Is A Real Bug

The fail packet is unauthenticated and not tied to the active peer’s UDP endpoint. Because server-side peers are keyed by external IP, any host sharing the peer’s public IP can spoof a fail condition from an arbitrary source port.

This allows a practical denial of service against an established tunnel without knowing tunnel keys or completing a protocol exchange.

## Fix Requirement

A `HANDSHAKE_FAIL` packet must not remove an active peer solely because the source IP matches. It must either be authenticated or, at minimum, match the expected peer network endpoint, including source port.

## Patch Rationale

The patch adds a source-port check:

```python
if addr[1] == peer.get_pqcport() and peer.get_state() in (
    PeerState.ESTABLISHED,
    PeerState.NEW,
):
```

This prevents same-public-IP attackers using arbitrary UDP source ports from deleting the peer. The change preserves existing behavior for fail packets that arrive from the peer’s known PQConnect port.

## Residual Risk

None

## Patch

```diff
diff --git a/src/pqconnect/tundevice.py b/src/pqconnect/tundevice.py
index ca545ff..07c88dd 100644
--- a/src/pqconnect/tundevice.py
+++ b/src/pqconnect/tundevice.py
@@ -410,7 +410,10 @@ class TunDevice:
         elif pkt == HANDSHAKE_FAIL:
             if addr[0] in self._ext2peer.keys():
                 peer = self._ext2peer[addr[0]]
-                if peer.get_state() in (PeerState.ESTABLISHED, PeerState.NEW):
+                if addr[1] == peer.get_pqcport() and peer.get_state() in (
+                    PeerState.ESTABLISHED,
+                    PeerState.NEW,
+                ):
                     logger.error("Handshake failed")
                     peer.error()
                     self.remove_peer(peer)
```