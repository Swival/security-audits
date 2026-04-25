# Seal counter wraps

## Classification

Vulnerability: low severity. Confidence: certain.

## Affected Locations

`src/crypto/hpke/hpke.go:174`

## Summary

`Sender.Seal` increments a `uint64` sequence counter without checking overflow. After `2^64` successful seal operations, the counter wraps to `0`, causing `nextNonce()` to derive a nonce previously used with the same AEAD key.

## Provenance

Verified from the provided finding and reproduced source analysis. Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A single HPKE `Sender` context is used for `2^64` successful `Seal` calls, then used again.

## Proof

`Sender.Seal` calls `s.aead.Seal(nil, s.nextNonce(), plaintext, aad)` and then increments `s.seqNum`.

`seqNum` is a `uint64`; Go integer overflow wraps modulo `2^64`. When `seqNum == math.MaxUint64`, a successful seal increments it back to `0`.

`nextNonce()` derives the AEAD nonce from the current `seqNum` encoded into the nonce suffix and XORed with `baseNonce`. Once `seqNum` wraps to `0`, the derived nonce matches the initial nonce for the same sender context and AEAD key.

## Why This Is A Real Bug

HPKE requires nonce uniqueness for each encryption under a given AEAD key. The implementation does not enforce the sequence-number exhaustion condition, so nonce reuse is possible after counter wrap. The trigger is impractical in ordinary use but the overflow path is direct and source-supported.

## Fix Requirement

Before sealing, reject `Seal` when `seqNum == math.MaxUint64`. Increment `seqNum` only after successful encryption.

## Patch Rationale

The patch adds an explicit exhaustion check before encryption and preserves the existing sequence counter until `aead.Seal` succeeds. This prevents the terminal `math.MaxUint64` seal from wrapping the counter to `0`, ensuring the sender context cannot reuse the initial nonce.

## Residual Risk

None

## Patch

`009-seal-counter-wraps.patch`