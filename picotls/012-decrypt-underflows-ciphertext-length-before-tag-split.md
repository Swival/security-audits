# Decrypt underflows ciphertext length before tag split

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/ptlsbcrypt.c:415`

## Summary
`ptls_bcrypt_aead_do_decrypt` subtracts `ctx->super.algo->tag_size` from attacker-controlled `inlen` before validating that the ciphertext is long enough to contain an AEAD tag. If `inlen < tag_size`, `size_t` underflows, `pbTag` is derived from an out-of-bounds offset, and `BCryptDecrypt` is called with a wrapped `ULONG` length.

## Provenance
- Verified from reproduced behavior and code inspection
- Scanner reference: https://swival.dev

## Preconditions
- Attacker-controlled ciphertext shorter than the AEAD tag size reaches `ptls_bcrypt_aead_do_decrypt`

## Proof
In `lib/ptlsbcrypt.c:415`, `textLen = inlen - ctx->super.algo->tag_size` is computed before any guard on `inlen`. For inputs shorter than the tag:
- `textLen` underflows as `size_t`
- `pbTag` is set to `input + textLen`, producing an invalid tag pointer
- `BCryptDecrypt` receives `(ULONG)textLen` as the ciphertext length and output length

This path is reachable from the AEAD decrypt callback. The reproduced trace also confirms an attacker-controlled path through ECH handling: `ch->ech.payload.len` is sourced from the ClientHello payload in `lib/picotls.c:3879` and passed to `ptls_aead_decrypt` in `lib/picotls.c:4421` without a `>= tag_size` check.

## Why This Is A Real Bug
AEAD decryption requires ciphertext length to be at least the authentication tag length before splitting ciphertext and tag. Failing that invariant causes integer underflow and forwards invalid pointer/length state into the Windows CNG API. This is a concrete memory-safety and availability issue, with at least crash or denial-of-service impact from malformed attacker input.

## Fix Requirement
Reject inputs where `inlen < ctx->super.algo->tag_size` before subtracting or deriving the tag pointer, and return failure without calling `BCryptDecrypt`.

## Patch Rationale
The patch adds an early length check in `ptls_bcrypt_aead_do_decrypt` so the function exits on undersized ciphertext before computing `textLen`, setting `pbTag`, or invoking `BCryptDecrypt`. This enforces the AEAD minimum-length invariant at the backend boundary and removes dependence on caller-side validation.

## Residual Risk
None

## Patch
- Added a guard in `lib/ptlsbcrypt.c` to return failure when `inlen` is smaller than `ctx->super.algo->tag_size`
- Moved the subtraction/tag split behind that validation so `textLen` cannot underflow
- Prevented invalid `pbTag` derivation and wrapped `(ULONG)textLen` values from reaching `BCryptDecrypt`
- Patch file: `012-decrypt-underflows-ciphertext-length-before-tag-split.patch`