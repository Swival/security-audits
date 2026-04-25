# Absorbing State Allows Full Buffer

## Classification

Invariant violation. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/sha3/sha3.go:222`

## Summary

`UnmarshalBinary` accepts a marshaled SHA3 digest with `state == spongeAbsorbing` and `n == d.rate`. This creates an impossible full absorbing buffer state that normal absorption would have permuted away, allowing later `Sum`/read paths to violate the SHA3 padding invariant.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Attacker controls marshaled `Digest` bytes for a matching SHA3 variant.

## Proof

`UnmarshalBinary` reads `n` and `state` from attacker-controlled input, rejects only `n > d.rate`, then assigns `d.n` and `d.state`.

For SHA3-256, a concrete accepted blob is 207 bytes:

- Magic: `sha\x08`
- Rate: `136`
- State bytes: any 200 bytes
- Final bytes: `{136, 0}` for `n == rate` and `spongeAbsorbing`

After unmarshalling, `Sum(nil)` reaches:

- `crypto/sha3.(*SHA3).UnmarshalBinary` delegates to the affected internal code at `src/crypto/sha3/sha3.go:178`
- `Sum` reaches `sumGeneric -> readGeneric -> padAndPermute`
- `padAndPermute` writes `d.dsbyte` at `d.a[d.n]` at `src/crypto/internal/fips140/sha3/sha3.go:87`

With `n == rate`, padding is applied to a full absorbing buffer, contradicting the invariant documented at `src/crypto/internal/fips140/sha3/sha3.go:83` that a full buffer should already have been permuted.

## Why This Is A Real Bug

Normal absorbing logic never leaves `d.n == d.rate` in `spongeAbsorbing`; it permutes and resets `d.n = 0`. Accepting this state through unmarshalling bypasses that invariant and lets public APIs compute from an impossible SHA3 sponge state.

This is not memory corruption because `d.a` is 200 bytes and SHA3 rates are below 200, but it is a real logical and cryptographic invariant violation.

## Fix Requirement

Reject marshaled digests where `state == spongeAbsorbing` and `n == d.rate`.

## Patch Rationale

The patch adds validation in `UnmarshalBinary` so deserialization cannot create an absorbing state that the normal update path would never produce. This preserves the existing acceptance of valid partial absorbing buffers while rejecting only the impossible full-buffer absorbing case.

## Residual Risk

None

## Patch

`058-absorbing-state-allows-full-buffer.patch`