# AEAD constructor failure is reported as success

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/hpke.c:172`
- `lib/hpke.c:235`
- `lib/hpke.c:256`
- `include/picotls.h:1950`
- `include/picotls.h:1956`
- `lib/ptlsbcrypt.c:515`
- `lib/ptlsbcrypt.c:566`
- `lib/picotls.c:2371`
- `lib/picotls.c:2488`
- `lib/picotls.c:2204`

## Summary
`key_schedule` in `lib/hpke.c` assigns `*ctx = ptls_aead_new_direct(...)` but does not convert a `NULL` result into an error. When AEAD construction fails, the function still returns success (`0`) and leaves callers with `*ctx == NULL`. This creates a false-success condition in both `ptls_hpke_setup_base_s` and `ptls_hpke_setup_base_r`.

## Provenance
- Verified from reproduced behavior and source inspection.
- Reproducer demonstrates reachable AEAD-constructor failure via bcrypt-backed setup failures in `lib/ptlsbcrypt.c`.
- Reference: Swival Security Scanner - https://swival.dev

## Preconditions
- `ptls_aead_new_direct` returns `NULL` during HPKE setup.

## Proof
- `ptls_hpke_setup_base_s` and `ptls_hpke_setup_base_r` call `key_schedule` at `lib/hpke.c:235` and `lib/hpke.c:256`.
- In `key_schedule` at `lib/hpke.c:172`, HKDF-derived `key` and `base_nonce` are computed, then `*ctx = ptls_aead_new_direct(...)` is executed.
- No subsequent check updates `ret` when `*ctx == NULL`.
- The function therefore returns the prior success value (`ret == 0`) while the output context remains `NULL`.
- The reproducer confirms a concrete trigger through constructor failure paths in `lib/ptlsbcrypt.c:515` and `lib/ptlsbcrypt.c:566`.

## Why This Is A Real Bug
The exported HPKE setup APIs document that they return an AEAD context on success in `include/picotls.h:1950` and `include/picotls.h:1956`. Returning success with `*ctx == NULL` violates that contract and exposes inconsistent caller-visible state. This is not theoretical: client ECH setup checks only the return code at `lib/picotls.c:2371`, so a false-success path leaves `tls->ech.aead == NULL`; later logic treats that as absence of ECH and emits a clear outer ClientHello at `lib/picotls.c:2488` and `lib/picotls.c:2204` instead of encrypting ECH.

## Fix Requirement
After calling `ptls_aead_new_direct`, `key_schedule` must return an error when `*ctx == NULL` before reporting success to the caller.

## Patch Rationale
The patch adds an immediate post-construction `NULL` check in `key_schedule` and converts constructor failure into an error return. This preserves the API contract that successful HPKE setup yields a usable AEAD context and prevents downstream logic from acting on a false-success result.

## Residual Risk
None

## Patch
- Patch file: `010-aead-constructor-failure-is-reported-as-success.patch`
- Change: add a `NULL` check after `ptls_aead_new_direct(...)` in `lib/hpke.c` and return an error if AEAD construction failed.