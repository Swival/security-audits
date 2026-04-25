# XOR Counter Nonce Skips Allowed

## Classification

Invariant violation; medium severity; confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/aes/gcm/gcm_nonces.go:273`

## Summary

`GCMWithXORCounterNonce.Seal` accepted XOR-counter nonce values greater than the expected next counter. This allowed callers in FIPS mode to skip counter values even though the documented invariant requires each subsequent call to increment the counter exactly once.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- FIPS mode is enabled.
- Caller uses `GCMWithXORCounterNonce`.
- Caller supplies XOR-counter nonces to `Seal`.

## Proof

Nonce bytes enter `GCMWithXORCounterNonce.Seal`, are decoded, and are XORed with `g.mask` into `counter`.

The implementation only rejected counters lower than `g.next`:

```go
if counter < g.next {
    panic(...)
}
g.next = counter + 1
```

After a call with counter `0`, `g.next` becomes `1`. A later call with counter `2` passes because `2 < 1` is false, then advances `g.next` to `3`.

This contradicts the documented invariant that each subsequent call must increment the counter. The existing test evidence also showed an accepted skip from `1` to `100` in `src/crypto/cipher/gcm_fips140v1.26_test.go`.

## Why This Is A Real Bug

The implementation enforced monotonic non-decrease, not consecutive increment. As a result, skipped XOR-counter nonces still reached FIPS approval recording and encryption. This weakened nonce-construction validation against the documented rule, even though it did not directly create nonce reuse.

## Fix Requirement

Require `counter == g.next` before advancing `g.next`, while preserving the existing `MaxUint64` exhaustion handling.

## Patch Rationale

The patch changes validation from “not less than next” to “exactly equal to next.” This aligns runtime behavior with the documented invariant: every successful `Seal` call must consume the next consecutive XOR-counter value.

## Residual Risk

None

## Patch

`033-xor-counter-nonce-skips-allowed.patch`