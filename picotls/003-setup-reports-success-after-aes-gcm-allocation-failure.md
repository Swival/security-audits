# Setup reports success after AES-GCM allocation failure

## Classification
- Type: error-handling bug
- Severity: high
- Confidence: certain

## Affected Locations
- `lib/fusion.c:889`
- `lib/fusion.c:921`
- `lib/fusion.c:1141`
- `lib/fusion.c:1161`
- `lib/fusion.c:1424`
- `lib/fusion.c:1687`
- `lib/fusion.c:1886`
- `lib/fusion.c:1103`
- `lib/fusion.c:1045`
- `lib/picotls.c:6497`

## Summary
`aesgcm_setup` and `non_temporal_setup` store the result of `new_aesgcm(...)` into `ctx->aesgcm` and return success without checking for allocation failure. If `aligned_alloc(32, ctx_size)` fails inside `new_aesgcm`, setup still reports success with `ctx->aesgcm == NULL`, leaving the AEAD object in an invalid state that later crashes on use or free.

## Provenance
- Reproduced from the verified finding and source review
- Scanner source: https://swival.dev

## Preconditions
- `new_aesgcm` allocation fails during AEAD setup

## Proof
- `new_aesgcm` returns `NULL` when `aligned_alloc(32, ctx_size)` fails.
- `aesgcm_setup` assigns `ctx->aesgcm = new_aesgcm(...)` and returned success unconditionally at `lib/fusion.c:889`.
- `non_temporal_setup` performs the same unchecked assignment and returned success unconditionally at `lib/fusion.c:921`.
- Later code dereferences `ctx->aesgcm` without a NULL guard:
  - `aead_do_encrypt` reads `ctx->aesgcm->capacity` at `lib/fusion.c:1141`
  - `aead_do_decrypt` reads `ctx->aesgcm->capacity` at `lib/fusion.c:1161`
  - non-temporal paths dereference the AEAD context at `lib/fusion.c:1424`, `lib/fusion.c:1687`, and `lib/fusion.c:1886`
- Freeing the context also crashes:
  - `ptls_aead_free` always invokes `ctx->dispose_crypto(ctx)` at `lib/picotls.c:6497`
  - `aesgcm_dispose_crypto` forwards `ctx->aesgcm` to `ptls_fusion_aesgcm_free` at `lib/fusion.c:1103`
  - `ptls_fusion_aesgcm_free` immediately dereferences the pointer at `lib/fusion.c:1045`

## Why This Is A Real Bug
This is a concrete NULL-dereference reachable after an out-of-memory condition. The setup path violates its contract by signaling success while leaving required state uninitialized. The result is deterministic process termination on subsequent encrypt, decrypt, or even object cleanup.

## Fix Requirement
Both setup functions must validate the `new_aesgcm(...)` result and return an allocation error instead of success when it is `NULL`.

## Patch Rationale
The patch in `003-setup-reports-success-after-aes-gcm-allocation-failure.patch` adds post-allocation checks in the AEAD setup paths and propagates failure immediately. This aligns the return value with the actual initialization state and prevents later NULL dereferences in operational and cleanup paths.

## Residual Risk
None

## Patch
```diff
diff --git a/lib/fusion.c b/lib/fusion.c
index XXXXXXX..YYYYYYY 100644
--- a/lib/fusion.c
+++ b/lib/fusion.c
@@ -886,7 +886,10 @@ static int aesgcm_setup(ptls_fusion_aesgcm_context_t *ctx, int is_enc, const voi
     ptls_fusion_aesecb_init(&ctx->ecb, is_enc, key);
     ctx->ghash = ghash;
     ctx->aesgcm = new_aesgcm(&ctx->ecb, &ctx->ghash, capacities, non_temporal);
-    return 0;
+    if (ctx->aesgcm == NULL)
+        return PTLS_ERROR_NO_MEMORY;
+
+    return 0;
 }
 
@@ -918,7 +921,10 @@ static int non_temporal_setup(ptls_fusion_aesgcm_context_t *ctx, int is_enc, con
     ptls_fusion_aesecb_init(&ctx->ecb, is_enc, key);
     ctx->ghash = ghash;
     ctx->aesgcm = new_aesgcm(&ctx->ecb, &ctx->ghash, capacities, non_temporal);
-    return 0;
+    if (ctx->aesgcm == NULL)
+        return PTLS_ERROR_NO_MEMORY;
+
+    return 0;
 }
```