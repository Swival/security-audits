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
`key_schedule` derives HPKE key material and then constructs the AEAD context with `ptls_aead_new_direct(...)`. If that constructor returns `NULL`, the function leaves `ret` unchanged and returns success. As a result, `ptls_hpke_setup_base_s` and `ptls_hpke_setup_base_r` can report success while returning a `NULL` AEAD context, violating the documented API contract and exposing callers to false-success behavior.

## Provenance
- Verified finding reproduced from the provided trigger path and code inspection
- Source: Swival Security Scanner - https://swival.dev

## Preconditions
- `ptls_aead_new_direct` returns `NULL` during HPKE setup

## Proof
In `lib/hpke.c:172`, `key_schedule` assigns:
```c
*ctx = ptls_aead_new_direct(aead, 1, key, base_nonce);
```
No error is recorded if this returns `NULL`. Therefore, when all prior HKDF steps succeed, `ret` remains `0` and the function returns success with `*ctx == NULL`.

This is reachable from both HPKE setup entrypoints:
- `ptls_hpke_setup_base_s` at `lib/hpke.c:235`
- `ptls_hpke_setup_base_r` at `lib/hpke.c:256`

The reproducer established a concrete trigger via AEAD backend failures in `lib/ptlsbcrypt.c:515` and `lib/ptlsbcrypt.c:566`, causing `ptls_aead_new_direct` to fail while `key_schedule` still returns `0`.

The resulting caller-visible state contradicts the API contract in:
- `include/picotls.h:1950`
- `include/picotls.h:1956`

A committed impact path exists in ECH setup:
- `lib/picotls.c:2371` checks only `ret`
- `lib/picotls.c:2488` and `lib/picotls.c:2204` later proceed with `tls->ech.aead == NULL`, treating it as no ECH and emitting a clear outer ClientHello

## Why This Is A Real Bug
This is not a theoretical inconsistency. The AEAD constructor has concrete failure paths, and those failures propagate as a false success to HPKE callers. The observable result is a successful return value paired with no usable AEAD context. In the reproduced ECH path, that suppresses encryption and falls back to sending a clear outer ClientHello, which is a real security-impacting behavioral regression from an allocation or crypto-provider failure.

## Fix Requirement
After AEAD creation in `key_schedule`, detect `*ctx == NULL` and return an error instead of success.

## Patch Rationale
The patch adds an explicit post-construction check in `key_schedule` so AEAD initialization failure is converted into a non-zero error return before control reaches HPKE callers. This restores the documented success contract: success now implies a valid AEAD context.

## Residual Risk
None

## Patch
`010-aead-constructor-failure-is-reported-as-success.patch` adds a NULL check immediately after `ptls_aead_new_direct(...)` in `lib/hpke.c` and returns an error when AEAD context construction fails.