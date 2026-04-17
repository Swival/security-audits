# One-shot ECDH ignores key generation failure

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/uecc.c:101`
- `lib/picotls.c:4733`

## Summary
`secp256r1_key_exchange` in `lib/uecc.c:101` calls `uECC_make_key(pub + 1, priv, ...)` but does not check whether key generation succeeded before using `priv` in `uECC_shared_secret`. On key-generation failure, the function can consume stale or uninitialized stack data, emit a public key buffer derived from bad state, and return success if `uECC_shared_secret` accepts the bytes.

## Provenance
- Verified by reproduction in an isolated worktree with a targeted harness
- Scanner source: https://swival.dev

## Preconditions
- `uECC_make_key` returns failure during secp256r1 exchange

## Proof
- At `lib/uecc.c:101`, `secp256r1_key_exchange` invokes `uECC_make_key(pub + 1, priv, uECC_secp256r1())` and ignores the return value.
- The same stack `priv` buffer is then passed to `uECC_shared_secret(peerkey.base + 1, priv, secret, uECC_secp256r1())`.
- Reproduction forced `uECC_make_key` to fail once while pre-filling the pending `priv` and `pub` buffers with known junk bytes to model stale memory.
- The observed execution was `make_key=0` followed by `shared_secret=1`, with a 32-byte secret emitted and a published key beginning `04aaaaaa`.
- The handshake path is reachable from `lib/picotls.c:4733`, where a `0` return from the exchange function is treated as success and the returned `ecdh_secret` and `pubkey` are used.

## Why This Is A Real Bug
The implementation is intended to abort if ephemeral key generation fails. Instead, it proceeds into secret derivation using invalid private-key material and can report success. That is a direct control-flow error, not a theoretical concern: the reproduced run shows the key-generation failure path is skipped and cryptographic state is derived from stale memory on a reachable TLS handshake path.

## Fix Requirement
Abort immediately when `uECC_make_key` fails, before reading `priv`, deriving a shared secret, or exposing `pub`.

## Patch Rationale
The patch in `008-one-shot-ecdh-ignores-key-generation-failure.patch` adds an explicit return-value check for `uECC_make_key` in `lib/uecc.c`. This enforces fail-closed behavior at the actual fault point and prevents both secret derivation and public-key output from invalid state.

## Residual Risk
None

## Patch
`008-one-shot-ecdh-ignores-key-generation-failure.patch` updates `lib/uecc.c` so `secp256r1_key_exchange` returns failure if `uECC_make_key` does not succeed, before `priv` or `pub` are consumed.