# Signature generation failure ignored

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/uecc.c:139`

## Summary
`secp256r1sha256_sign` ignores the boolean return value from `uECC_sign`. When signing fails, the function still DER-encodes the `sig` buffer, returns success, and selects ECDSA, violating the invariant that emitted signature bytes must come from a successful signing operation.

## Provenance
- Verified by reproduction on the target codebase
- Scanner source: https://swival.dev

## Preconditions
- `uECC_sign` returns failure during certificate signing

## Proof
The signer hashes attacker-influenced handshake `input`, then calls `uECC_sign(self->key, hash, sizeof(hash), sig, uECC_secp256r1())` at `lib/uecc.c:139`. Its return value is ignored. Reproduction forced signing failure and observed:
- function returned `0`
- callback reported success and selected `0x0403`
- emitted DER was `3006020100020100`

That DER decodes to `SEQUENCE { INTEGER 0, INTEGER 0 }`, i.e. `r=0, s=0`, which is not a valid ECDSA signature. This proves the function can report success and output a signature object not produced by a successful signer.

## Why This Is A Real Bug
This is not a theoretical API misuse. Under an actual signing-error condition, the code emits syntactically valid ASN.1 while falsely signaling success to the caller. That causes deterministic authentication failure and breaks error propagation at a security boundary. The reproduced `r=0, s=0` output demonstrates externally observable incorrect behavior.

## Fix Requirement
Check the return value of `uECC_sign`; if signing fails, wipe the temporary signature buffer and return an error before DER encoding or setting a successful algorithm result.

## Patch Rationale
The patch adds explicit failure handling immediately after `uECC_sign`. On failure it clears `sig` and aborts, preserving the invariant that any DER-encoded output must originate from a successful ECDSA operation and preventing false success from propagating to the handshake.

## Residual Risk
None

## Patch
- Patched in `009-signature-generation-failure-ignored.patch`
- Change required in `lib/uecc.c:139` to gate DER encoding on successful `uECC_sign` completion