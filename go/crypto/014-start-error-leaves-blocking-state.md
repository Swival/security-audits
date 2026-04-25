# Start Error Leaves Blocking State

## Classification

Logic error, low severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/quic.go:217`

## Summary

`QUICConn.Start` sets `q.conn.quic.started = true` before validating `Config.MinVersion`. If the MinVersion check fails, the `started` flag remains true, so a subsequent corrected call to `Start` is rejected with "Start called more than once" instead of being allowed to proceed.

## Provenance

Inferred from the provided patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller creates a `QUICConn` with `Config.MinVersion < VersionTLS13`.
- Caller invokes `Start`, which fails on the MinVersion check.
- Caller corrects the configuration and calls `Start` again.

## Proof

`Start` checks `q.conn.quic.started` first, returning an error if true. It then sets `started = true` before validating MinVersion. When the MinVersion check fails and returns early, `started` is already true. Any subsequent call to `Start` hits the `started` guard and returns "Start called more than once", regardless of whether the configuration has been corrected.

## Why This Is A Real Bug

The `started` flag is intended to prevent double-initialization, but setting it before validation makes an early error path permanently block retries. The QUIC connection is left in a state where it cannot be started and has not been fully initialized.

## Fix Requirement

Move `q.conn.quic.started = true` to after all pre-handshake validation succeeds.

## Patch Rationale

The patch moves the `started = true` assignment to after the MinVersion check. This preserves the double-start guard while ensuring that early validation failures do not leave the connection in a permanently blocked state.

## Residual Risk

None

## Patch

`014-start-error-leaves-blocking-state.patch`
