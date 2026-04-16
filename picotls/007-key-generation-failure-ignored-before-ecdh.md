# Keygen failure proceeds into ECDH state

## Classification
- Severity: Medium
- Type: error-handling bug
- Confidence: certain

## Affected Locations
- `lib/uecc.c:76`
- `lib/uecc.c:119`

## Summary
- `secp256r1_create_key_exchange` and `secp256r1_key_exchange` call `uECC_make_key(...)` and ignore its return value.
- When key generation fails, execution still publishes `ctx->pub` or uses `priv` in `uECC_shared_secret(...)`.
- This permits invalid public-key output and ECDH on uninitialized or otherwise invalid private-key material.

## Provenance
- Verified from the provided reproducer and source analysis in `lib/uecc.c`.
- External reference: `https://swival.dev`

## Preconditions
- `uECC_make_key` returns failure during secp256r1 key generation.

## Proof
- In `secp256r1_create_key_exchange`, `uECC_make_key(ctx->pub, priv, curve);` is called and unchecked at `lib/uecc.c:76`.
- The function then continues to expose `ctx->super.pubkey = &ctx->pub;`, making `ctx->pub` externally consumable even if key generation failed.
- In `secp256r1_key_exchange`, `uECC_make_key(pub, priv, curve);` is likewise unchecked at `lib/uecc.c:119`.
- The function then proceeds into `uECC_shared_secret(peerkey->key.base, priv, secret->base, curve);`.
- The reproducer further shows `uECC_shared_secret` consumes caller-provided private-key bytes without rejecting an out-of-range scalar before use in `deps/micro-ecc/uECC.c:1063`, `deps/micro-ecc/uECC.c:1073`, and `deps/micro-ecc/uECC.c:1084`.
- Therefore, a keygen failure can leave invalid key material in use and still reach observable protocol behavior.

## Why This Is A Real Bug
- The code assumes successful key generation before publishing a public key or deriving a shared secret, but does not enforce that invariant.
- On failure, it can send a bogus public key on the wire or derive a secret from undefined private-key bytes.
- Even if some failure modes later abort the handshake, the vulnerable behavior is real because the invalid state transition already occurred and is reachable on normal key-exchange paths.

## Fix Requirement
- Check the return value of `uECC_make_key(...)` in both functions.
- On failure, clear any transient key material, avoid publishing invalid state, free allocated context where applicable, and return an error.

## Patch Rationale
- The patch in `007-key-generation-failure-ignored-before-ecdh.patch` adds explicit `uECC_make_key(...)` result checks at both call sites.
- It fails closed before `ctx->pub` is exposed or `uECC_shared_secret(...)` is invoked.
- It also clears/frees state on the error path so callers cannot observe partially initialized key material.

## Residual Risk
- None

## Patch
```diff
diff --git a/lib/uecc.c b/lib/uecc.c
index 0000000..0000000 100644
--- a/lib/uecc.c
+++ b/lib/uecc.c
@@
-    uECC_make_key(ctx->pub, priv, curve);
+    if (!uECC_make_key(ctx->pub, priv, curve)) {
+        ptls_clear_memory(priv, sizeof(priv));
+        free(ctx);
+        return NULL;
+    }
@@
-    uECC_make_key(pub, priv, curve);
+    if (!uECC_make_key(pub, priv, curve)) {
+        ptls_clear_memory(priv, sizeof(priv));
+        ptls_clear_memory(pub, sizeof(pub));
+        return PTLS_ERROR_NO_MEMORY;
+    }
```