# Unchecked AES-GCM resize NULL-dereference on encrypt

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/fusion.c:824`
- `lib/fusion.c:1161`
- `lib/fusion.c:1162`
- `lib/fusion.c:1163`
- `lib/fusion.c:1204`

## Summary
`aead_do_encrypt` grows the Fusion AES-GCM context when `inlen + aadlen` exceeds the current capacity, but it assigns the return value of `ptls_fusion_aesgcm_set_capacity` directly into `ctx->aesgcm` without checking for `NULL`. If allocation fails, the next call into `ptls_fusion_aesgcm_encrypt` dereferences a null context and crashes. The same unchecked resize pattern exists on decrypt, and initial context creation is also assigned without a null check.

## Provenance
- Verified from the provided reproducer and source inspection
- Scanner provenance: https://swival.dev

## Preconditions
- Heap allocation fails during AES-GCM capacity growth
- Caller supplies input large enough to exceed the current Fusion AES-GCM capacity

## Proof
`ptls_fusion_aesgcm_set_capacity` returns `NULL` on allocation failure at `lib/fusion.c:824`. `aead_do_encrypt` invokes that helper when `inlen + aadlen` exceeds `ctx->aesgcm->capacity`, stores the result back into `ctx->aesgcm`, and then immediately calls `ptls_fusion_aesgcm_encrypt(ctx->aesgcm, ...)` without a null check. `ptls_fusion_aesgcm_encrypt` dereferences `_ctx` unconditionally, so an allocation failure becomes a reachable null-dereference crash.

The trigger is reachable from public API use: Fusion AEAD contexts start with capacity `1500` at `lib/fusion.c:1204`, and `ptls_aead_encrypt` forwards caller-controlled lengths into the backend. Any sufficiently large encrypt request enters the resize path. Equivalent unchecked reassignment is also present on decrypt at `lib/fusion.c:1161`, `lib/fusion.c:1162`, and `lib/fusion.c:1163`.

## Why This Is A Real Bug
This is a concrete denial-of-service condition, not a theoretical concern. The failing allocator path is explicitly represented in the code, the return value is documented by behavior as nullable, and the null result is consumed immediately by code that dereferences it unconditionally. Because input lengths are caller-controlled through the public AEAD API, the resize path is reachable in normal operation whenever a record exceeds the small initial capacity.

## Fix Requirement
Preserve the previous AES-GCM context until resize succeeds, and fail the encrypt or decrypt operation cleanly if resize returns `NULL`. Initial AES-GCM context construction must also be checked before storing or using the pointer.

## Patch Rationale
The patch in `002-unchecked-aes-gcm-resize-null-dereference-on-encrypt.patch` adds null checks around AES-GCM context allocation and resize sites. It avoids clobbering the live context on failure, returns an error instead of proceeding with a null pointer, and applies the same protection to decrypt and initial construction so all confirmed variants of the bug are closed consistently.

## Residual Risk
None

## Patch
- Patch file: `002-unchecked-aes-gcm-resize-null-dereference-on-encrypt.patch`
- Patched area: `lib/fusion.c`
- Effect: allocation failure during Fusion AES-GCM initialization or capacity growth no longer causes a null-dereference; the operation fails safely instead