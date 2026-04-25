# Shared XOR Nonce Race

## Classification

Race condition, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/tls/cipher_suites.go:484`

## Summary

TLS 1.3/ChaCha `xorNonceAEAD` mutates shared `nonceMask` inside `Seal` and `Open` while deriving per-record nonces. Concurrent use of the same AEAD instance can interleave those mutations, causing the underlying AEAD to receive a corrupted nonce and potentially leaving `nonceMask` inconsistent.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Same `xorNonceAEAD` instance is used by concurrent callers.

## Proof

The vulnerable implementation derives the per-call nonce by XORing the caller nonce into `f.nonceMask`, passing `f.nonceMask[:]` to the underlying AEAD, then XORing it back.

A concrete interleaving corrupts the nonce:

1. Goroutine A calls `Seal` with nonce A and mutates `nonceMask` to `mask ^ A`.
2. Goroutine B calls `Seal` with nonce B before A's underlying AEAD consumes the nonce.
3. Shared state becomes `mask ^ A ^ B`.
4. Goroutine A's underlying AEAD observes `mask ^ A ^ B`, not `mask ^ A`.
5. XOR-back interleavings can also leave the stored `nonceMask` inconsistent.

A scheduled harness using the same `xorNonceAEAD.Seal` logic and a fake AEAD that delays nonce capture reproduced the corruption:

```text
first Seal expected nonce: 00010203a4a4a4a4acacacac
first Seal observed nonce: 000102031415161718191a1b
mask^nonceA^nonceB:      000102031415161718191a1b
observed corrupted:       true
```

## Why This Is A Real Bug

AEAD implementations are commonly used concurrently, and callers receiving an AEAD value do not get synchronization guarantees from `xorNonceAEAD`. Because nonce derivation mutates shared state, concurrent `Seal` or `Open` calls can use an unintended nonce. This can cause authentication failure, decryption failure, or encryption/decryption under the wrong nonce.

## Fix Requirement

Derive the XOR nonce in a per-call local buffer. `Seal` and `Open` must never mutate shared `nonceMask`.

## Patch Rationale

The patch copies `nonceMask` into a local array, XORs the caller nonce into that local array, and passes the local nonce to the underlying AEAD. This preserves the intended nonce derivation while removing shared mutable state from the `Seal` and `Open` call paths.

## Residual Risk

None

## Patch

`027-shared-xor-nonce-race.patch`