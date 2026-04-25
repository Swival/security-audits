# Public Key Aliases Caller Buffer

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/ecdsa/ecdsa.go:201`

## Summary

`NewPublicKey` validates caller-provided public key bytes but stores the original `Q` slice in `PublicKey.q`. Because the returned key aliases caller-controlled storage, the caller can mutate `Q` after validation and alter the internal public key state. `NewPrivateKey` is also affected because it constructs and shallow-copies the aliased `PublicKey`.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller retains the `Q` slice after a successful `NewPublicKey` or `NewPrivateKey` call.

## Proof

- `NewPublicKey` validates `Q` with `SetBytes`, then returns `PublicKey{q: Q}`.
- `PublicKey.Bytes` returns `pub.q` directly, making post-construction mutation observable.
- `Verify` reparses `pub.q` through `SetBytes(pub.q)`, so mutated bytes can invalidate the key or replace it with another same-length valid public point.
- `NewPrivateKey` calls `NewPublicKey(c, Q)` and shallow-copies `*pub` into `priv.pub`, preserving the aliased backing array.
- A package-local reproducer confirmed the issue: construct a valid P-256 `Q`, call `NewPublicKey`, mutate `Q[0] = 0`, then observe `pub.Bytes()[0] == 0` and `SetBytes(pub.Bytes())` fails.

## Why This Is A Real Bug

A successfully constructed public key is expected to remain the validated key object unless modified through explicit API behavior. Here, external mutation of the original input slice changes internal cryptographic state after validation. This can cause verification failures, state corruption, or replacement with attacker-chosen public key material of the same length.

## Fix Requirement

`NewPublicKey` must copy validated public key bytes before storing them. If public key immutability is required by the API, `PublicKey.Bytes` must also return a copy rather than the internal slice.

## Patch Rationale

The patch stores a cloned copy of `Q` after validation, breaking the alias between caller-controlled input storage and `PublicKey.q`. Returning cloned bytes from `Bytes` prevents callers from mutating internal key state through the accessor.

## Residual Risk

None

## Patch

`023-public-key-aliases-caller-buffer.patch`