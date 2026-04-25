# Context Cancellation Can Close Completed Handshake

## Classification

Race condition; severity medium; confidence certain.

## Affected Locations

`src/crypto/tls/conn.go:1511`

## Summary

`HandshakeContext` installs a `context.AfterFunc` callback that closes the underlying `net.Conn` when the caller context is canceled. If cancellation races with a successful non-QUIC handshake return, the callback can close an already-completed TLS connection and the deferred cleanup can overwrite the successful return with `ctx.Err()`.

## Provenance

Verified from the reproduced finding and patched locally.

Scanner provenance: https://swival.dev

## Preconditions

Non-QUIC `HandshakeContext` is called with a cancelable context whose cancellation races with successful handshake completion.

## Proof

- `src/crypto/tls/conn.go:1535` installs `context.AfterFunc` for every non-QUIC handshake with a non-nil `ctx.Done()`.
- `src/crypto/tls/conn.go:1537` closes `c.conn` from the cancellation callback.
- Handshake success is recorded before returning nil, including `src/crypto/tls/handshake_client.go:618`, `src/crypto/tls/handshake_client_tls13.go:157`, `src/crypto/tls/handshake_server.go:128`, and `src/crypto/tls/handshake_server_tls13.go:102`.
- If cancellation occurs after the handshake succeeds but before the deferred `stop()` completes, `stop()` reports that the callback ran.
- The deferred cleanup then overwrites the nil return with `ctx.Err()`, so the caller receives `context.Canceled` and the completed TLS connection has been closed.

## Why This Is A Real Bug

The documented behavior is that context cancellation affects the handshake while it is in progress, not a connection whose handshake has already completed. The race allows a completed TLS connection to be closed underneath the caller and reported as canceled, violating that guarantee for reachable non-QUIC `HandshakeContext` calls.

## Fix Requirement

After the handshake finishes, cancellation cleanup must not close the connection or overwrite the return value when the handshake completed successfully.

## Patch Rationale

The patch suppresses the cancellation close/error path once handshake completion has been recorded. This preserves cancellation behavior while the handshake is still pending, but prevents a late racing context cancellation from invalidating a successfully established TLS connection.

## Residual Risk

None

## Patch

`005-context-cancellation-can-close-completed-handshake.patch`