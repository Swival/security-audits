# Unchecked ECH Hash Clone

## Classification

Error-handling bug, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/handshake_server_tls13.go:718`

## Summary

`sendServerParameters` calls `cloneHash(hs.transcript, hs.suite.hash)` during ECH server confirmation but does not check the return value for nil. `cloneHash` can return nil in several failure modes, and the subsequent `echTranscript.Write(...)` call panics on a nil receiver.

## Provenance

Inferred from the provided patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- ECH is negotiated (`hs.echContext != nil`).
- `cloneHash` fails due to a hash that does not support cloning, or a marshal/unmarshal failure.

## Proof

`cloneHash` returns nil in four scenarios:

- The hash does not implement `hash.Cloner` and does not support binary marshaling.
- `MarshalBinary()` returns an error.
- The new hash does not support `UnmarshalBinary`.
- `UnmarshalBinary()` returns an error.

At line 718, `echTranscript` receives the return value without a nil check. Line 719 then calls `echTranscript.Write(hs.clientHello.original)`, which panics with a nil pointer dereference.

## Why This Is A Real Bug

The ECH server confirmation path is reachable during a valid TLS 1.3 handshake with ECH. A hash clone failure during this path causes a server panic instead of sending an alert and returning an error. Other call sites of `cloneHash` in the same file check for nil, making this omission inconsistent.

## Fix Requirement

Check `echTranscript` for nil after `cloneHash` and return an internal error alert if cloning fails.

## Patch Rationale

The patch adds a nil check after `cloneHash`, sending `alertInternalError` and returning a descriptive error instead of panicking. This matches the error handling pattern used elsewhere in the same file.

## Residual Risk

None

## Patch

`017-unchecked-ech-hash-clone.patch`
