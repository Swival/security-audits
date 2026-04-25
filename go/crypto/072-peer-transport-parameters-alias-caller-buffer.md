# Peer transport parameters alias caller buffer

## Classification
- Type: trust-boundary violation
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/crypto/tls/quic.go:369`

## Summary
`QUICConn.SetTransportParameters` stored the caller-provided `params` slice directly in `q.conn.quic.transportParams`. The handshake later retrieved that same slice via `Conn.quicGetTransportParameters()` and used it for peer-visible TLS/QUIC processing. Because ownership was not severed at the API boundary, post-call mutations to the caller's backing array changed the transport parameters sent to the peer.

## Provenance
- Verified finding reproduced from scanner output associated with Swival Security Scanner: https://swival.dev
- Reproducer confirmed the aliased slice is later consumed from handshake paths including `src/crypto/tls/handshake_client.go:163` and `src/crypto/tls/handshake_server_tls13.go:781`

## Preconditions
- The caller mutates `params` after calling `SetTransportParameters`
- The handshake has not yet consumed `q.conn.quic.transportParams`

## Proof
At `src/crypto/tls/quic.go:369`, the original code performed a direct assignment:
```go
q.conn.quic.transportParams = params
```

The stored slice is later returned unchanged by `src/crypto/tls/quic.go` in `Conn.quicGetTransportParameters()`:
```go
return c.quic.transportParams, nil
```

The reproduced behavior established:
- On client and not-yet-started server paths, the handshake later marshals whatever bytes are currently present in that aliased slice from `src/crypto/tls/handshake_client.go:163` or `src/crypto/tls/handshake_server_tls13.go:781`
- On a started server, `SetTransportParameters` can complete while the handshake is still blocked in `quicWaitForSignal`, leaving time for the caller to mutate the shared backing array before `quicGetTransportParameters()` reads it

Therefore, application-owned memory remains live after handoff and directly controls peer-visible transport parameters.

## Why This Is A Real Bug
This is a real integrity and trust-boundary bug because `SetTransportParameters` accepts application-controlled input that should become internal connection state, but instead retains a shared reference to mutable caller memory. The API call implies handoff. Without a defensive copy, later unrelated caller writes silently alter handshake contents sent to the remote peer. The reproducer confirmed this is reachable in practical client and server states, so the behavior is not merely theoretical.

## Fix Requirement
Defensively copy `params` inside `QUICConn.SetTransportParameters` before storing it in `q.conn.quic.transportParams`.

## Patch Rationale
The patch replaces the direct slice assignment with:
```go
q.conn.quic.transportParams = append([]byte{}, params...)
```

This creates an owned copy of the transport parameters at the handoff boundary while preserving existing semantics for `nil` normalization and later handshake consumption. After the copy, subsequent caller mutations cannot affect internal state or peer-visible output.

## Residual Risk
None

## Patch
- Updated `src/crypto/tls/quic.go:369` to copy the caller buffer before storage
- Patched line:
```diff
-	q.conn.quic.transportParams = params
+	q.conn.quic.transportParams = append([]byte{}, params...)
```