# Concurrent Seal Nonce Reuse

## Classification

High severity race condition. Confidence: certain.

## Affected Locations

`src/crypto/hpke/hpke.go:173`

## Summary

Concurrent calls to exported `Sender.Seal` can reuse the same HPKE AEAD nonce because nonce derivation reads a shared, unsynchronized `seqNum`, and `seqNum` is incremented only after encryption completes.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

A shared `Sender` is used by multiple goroutines concurrently.

## Proof

`Sender.Seal` calls `s.nextNonce()` during `AEAD.Seal`, then increments `s.seqNum` afterward.

`nextNonce` derives the nonce from `baseNonce XOR seqNum`. Because `seqNum` is a plain `uint64` without mutex or atomic protection, two goroutines can observe the same sequence number before either increments it.

Both goroutines then encrypt under the same HPKE AEAD key and nonce.

## Why This Is A Real Bug

HPKE requires unique nonces per AEAD key. Reusing a nonce with AES-GCM or ChaCha20-Poly1305 breaks the confidentiality and integrity assumptions of the construction.

`Sender` is returned by `NewSender`, and `Seal` is exported, so concurrent use by callers is reachable.

## Fix Requirement

Nonce sequence allocation must be synchronized so each `Seal` call obtains a unique sequence number before encryption begins.

## Patch Rationale

The patch serializes sequence number use for `Sender.Seal`, ensuring nonce derivation and sequence advancement cannot race across goroutines.

This preserves the HPKE nonce uniqueness invariant while keeping the existing exported API unchanged.

## Residual Risk

None

## Patch

`008-concurrent-seal-nonce-reuse.patch`