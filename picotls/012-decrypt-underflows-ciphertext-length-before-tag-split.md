# Decrypt length underflow before tag split

## Classification
- Type: validation gap
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/ptlsbcrypt.c:415`

## Summary
`ptls_bcrypt_aead_do_decrypt` subtracts `ctx->super.algo->tag_size` from attacker-controlled `inlen` before validating that the ciphertext is at least one tag long. If `inlen < tag_size`, the `size_t` subtraction underflows, producing a wrapped `textLen`, an out-of-bounds `pbTag` pointer, and oversized lengths passed into `BCryptDecrypt`.

## Provenance
- Verified from the provided reproducer and source inspection
- Swival Security Scanner: https://swival.dev

## Preconditions
- Attacker-controlled ciphertext shorter than the AEAD tag size reaches `ptls_bcrypt_aead_do_decrypt`

## Proof
In `lib/ptlsbcrypt.c:415`, `textLen` is computed as `inlen - ctx->super.algo->tag_size` before any lower-bound check on `inlen`. For inputs shorter than the tag:
- `textLen` wraps to a large `size_t`
- `pbTag` becomes `input + textLen`, which points out of bounds
- `(ULONG)textLen` is passed to `BCryptDecrypt` as the ciphertext and output length

The reproducer established a concrete attacker-controlled path through ECH handling:
- `ch->ech.payload.len` is derived from ClientHello input at `lib/picotls.c:3879`
- It is passed to `ptls_aead_decrypt` at `lib/picotls.c:4421` without a `>= tag_size` check
- The bcrypt AEAD decrypt callback is therefore reachable with undersized ciphertext

## Why This Is A Real Bug
This is not a theoretical invariant violation. The backend performs tag splitting using unvalidated attacker-controlled length, then forwards the wrapped length and invalid tag pointer into the Windows crypto API. That creates real crash / denial-of-service potential and breaks the required AEAD precondition that ciphertext length must be at least the tag size.

## Fix Requirement
Reject `inlen < ctx->super.algo->tag_size` before subtracting or deriving the tag pointer, and return failure without calling `BCryptDecrypt`.

## Patch Rationale
The patch in `012-decrypt-underflows-ciphertext-length-before-tag-split.patch` adds the missing prevalidation at the start of `ptls_bcrypt_aead_do_decrypt`. This prevents `size_t` underflow, avoids constructing an out-of-bounds `pbTag`, and ensures `BCryptDecrypt` is never invoked with wrapped lengths for malformed short ciphertext.

## Residual Risk
None

## Patch
`012-decrypt-underflows-ciphertext-length-before-tag-split.patch`