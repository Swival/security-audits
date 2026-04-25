# Nil Remote Key Panic
## Classification
Error-handling bug, low severity. Confidence: certain.

## Affected Locations
`src/crypto/ecdh/ecdh.go:131`

## Summary
`PrivateKey.ECDH` dereferences the `remote` public key parameter before validating that it is non-nil. A caller can invoke `ECDH(nil)` and trigger a runtime nil-pointer panic instead of receiving an error.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
Caller passes a nil remote public key to `PrivateKey.ECDH`.

## Proof
`PrivateKey.ECDH(remote *PublicKey)` is public and accepts the peer public key directly. The implementation checks `remote.curve` before checking whether `remote` is nil. Therefore, calling `k.ECDH(nil)` with any valid private key dereferences a nil pointer and panics.

The reproducer confirmed:
- `PrivateKey.ECDH` is reachable through `crypto/ecdh`.
- It is also exposed through the `KeyExchanger` interface.
- `remote` reaches `ECDH` directly as nil.
- The first dereference of `remote.curve` triggers the panic.

## Why This Is A Real Bug
Public error-returning APIs should reject invalid caller input with an error when practical. This method already returns `(sharedSecret []byte, err error)`, but a nil remote key causes process-level panic behavior instead of normal error handling. Callers handling malformed or absent peer keys can crash unless they add external panic recovery.

## Fix Requirement
Check `remote == nil` before any dereference and return an error.

## Patch Rationale
The patch adds an explicit nil guard before the curve mismatch check. This preserves existing behavior for valid keys and mismatched curves while converting the nil input case from a panic into a normal error return.

## Residual Risk
None

## Patch
`042-nil-remote-key-panic.patch`