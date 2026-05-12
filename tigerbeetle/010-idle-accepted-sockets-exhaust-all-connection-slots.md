# Idle Accepted Sockets Exhaust Connection Slots

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/message_bus.zig:319`

## Summary

A replica stops accepting inbound connections when all finite connection slots are occupied. Unauthenticated remote peers can open TCP connections and send no data; each accepted socket consumes a slot while remaining `.unknown`, and no read/handshake timeout reclaims it. Filling all slots prevents legitimate client or replica inbound connections from being accepted.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Replica is listening.
- Connection slots are finite.
- Attacker can reach the replica TCP port.

## Proof

- `accept()` returns when `bus.connections_used == bus.connections.len`.
- A successful accept immediately marks the reserved connection `.connected`, stores the fd, increments `connections_used`, allocates a receive buffer, and submits `recv()`.
- Peer identity is not known at accept time; the connection remains `.unknown` until message headers are received and processed.
- An idle peer that keeps the TCP socket open but sends no bytes leaves the receive operation pending.
- Cleanup only happens after receive error, EOF, invalid data, or explicit termination.
- TCP keepalive does not mitigate a live attacker that ACKs keepalives.
- Repeating idle accepts until all slots are consumed makes `accept()` stop, blocking later legitimate inbound clients or replica peers.

## Why This Is A Real Bug

The connection-slot accounting is exhausted before authentication or peer classification. The existing control flow has no timeout or quota for accepted unknown peers, so idle unauthenticated sockets can persist indefinitely. Because `accept()` refuses to submit another accept while the slot pool is full, this becomes a remote unauthenticated denial of service against inbound connectivity.

## Fix Requirement

When no free connection slot is available, the bus must reclaim unauthenticated accepted sockets instead of letting unknown idle peers permanently block `accept()`. The fix must avoid repeatedly terminating multiple sockets concurrently and must preserve existing behavior when no unknown peer is available to reclaim.

## Patch Rationale

The patch changes the full-slot branch in `accept()` to look for reclaimable `.unknown` connections. If any connection is already terminating, it returns and waits for cleanup to complete. Otherwise, it terminates one unknown peer with shutdown and returns, allowing the slot to become free asynchronously. If no unknown peer exists, behavior remains unchanged and `accept()` returns.

This mirrors the existing `connect_reclaim_connection` helper at `src/message_bus.zig:404`, which already applies the same single-terminate-at-a-time pattern when the *outbound* replica connect path runs out of slots. The accept path was the asymmetric gap.

This directly addresses the reproduced failure mode: idle accepted sockets remain `.unknown`, so they are preferentially disconnected when they would otherwise exhaust the finite slot pool. Note that this is a partial mitigation, not a complete fix — a steady-state attacker can still race new SYNs against reclaimed slots. A complete fix would add a per-connection handshake timeout that demotes `.unknown` to `.free` after a bounded period; that is a larger change.

## Residual Risk

Partial mitigation only. The patch makes idle unknown peers reclaimable, but a sustained attacker that maintains a backlog of half-open or no-data connections can still keep most of the slot pool churning, racing the OS accept queue against the periodic reclaim. A complete fix should additionally bound the time a connection is allowed to remain `.unknown` (handshake/idle timeout) so reclamation does not depend on slot exhaustion to fire.

## Patch

```diff
diff --git a/src/message_bus.zig b/src/message_bus.zig
index 654a5d5e6..ee4c3a111 100644
--- a/src/message_bus.zig
+++ b/src/message_bus.zig
@@ -320,8 +320,22 @@ pub fn MessageBusType(comptime IO: type) type {
             assert(bus.accept_fd != null);
 
             if (bus.accept_connection != null) return;
-            // All connections are currently in use, do nothing.
-            if (bus.connections_used == bus.connections.len) return;
+            if (bus.connections_used == bus.connections.len) {
+                // Reclaim unauthenticated accepted sockets so idle peers can't block accept().
+                for (bus.connections) |*connection| {
+                    if (connection.state == .terminating) return;
+                }
+                for (bus.connections) |*connection| {
+                    if (connection.peer == .unknown) {
+                        log.info("{}: on_accept: no free connection, disconnecting unknown peer", .{
+                            bus.id,
+                        });
+                        bus.terminate(connection, .shutdown);
+                        return;
+                    }
+                }
+                return;
+            }
             assert(bus.connections_used < bus.connections.len);
             bus.accept_connection = for (bus.connections) |*connection| {
                 if (connection.state == .free) {
```