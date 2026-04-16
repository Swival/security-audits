# One-shot ECDH ignores key generation failure

## Classification
- Type: error-handling bug
- Severity: medium
- Confidence: certain

## Affected Locations
- `lib/uecc.c:101`

## Summary
- `secp256r1_key_exchange` calls `uECC_make_key(pub + 1, priv, uECC_secp256r1())` and does not check its return value.
- On failure, the function still uses stack `priv` bytes in `uECC_shared_secret(...)` and may return success with a derived secret and published key material sourced from stale memory.
- This skips the intended abort path for ephemeral key-generation failure on a reachable TLS handshake path.

## Provenance
- Verified by reproduction against the reported path and behavior.
- Scanner source: https://swival.dev
- Reachability confirmed via `lib/picotls.c:4733`, where a zero return from the exchange callback is treated as success.

## Preconditions
- `uECC_make_key` returns failure during secp256r1 exchange.

## Proof
- At `lib/uecc.c:101`, `secp256r1_key_exchange` invokes `uECC_make_key(pub + 1, priv, ...)` without checking the result, then immediately passes `priv` into `uECC_shared_secret(peerkey.base + 1, priv, ...)`.
- `uECC_shared_secret` can still succeed if the stale `priv` bytes represent an acceptable scalar and the peer public key is valid.
- Reproduction forced a single `uECC_make_key` failure, prefilled the would-be uninitialized `priv` and `pub` buffers, and executed the same call sequence.
- Observed result: `make_key=0`, then `shared_secret=1`, with a 32-byte secret emitted and a junk published key prefix `04aaaaaa`, demonstrating continued success after key-generation failure.

## Why This Is A Real Bug
- The function consumes invalid state after a failed cryptographic key-generation step instead of failing closed.
- The bug is reachable from the TLS server handshake path, so a transient RNG or keygen failure can be misreported as a successful exchange.
- This can publish stale stack-derived public-key bytes and derive a secret from unintended private-key material, violating expected handshake correctness and error handling.

## Fix Requirement
- Check the return value of `uECC_make_key` and abort immediately on failure before using `priv` or exposing `pub`.

## Patch Rationale
- The patch in `008-one-shot-ecdh-ignores-key-generation-failure.patch` adds an explicit `uECC_make_key` failure check in `secp256r1_key_exchange`.
- This enforces fail-closed behavior at the first fault site and prevents both stale private-key use and stale public-key publication.

## Residual Risk
- None

## Patch
```diff
diff --git a/lib/uecc.c b/lib/uecc.c
index 0000000..0000000 100644
--- a/lib/uecc.c
+++ b/lib/uecc.c
@@ -101,7 +101,9 @@ static int secp256r1_key_exchange(ptls_iovec_t *pubkey, ptls_iovec_t *secret, pt
     uint8_t priv[32];
     uint8_t pub[65];
     pub[0] = 4;
-    uECC_make_key(pub + 1, priv, uECC_secp256r1());
+    if (!uECC_make_key(pub + 1, priv, uECC_secp256r1()))
+        return PTLS_ERROR_NO_MEMORY;
+
     if (!uECC_shared_secret(peerkey.base + 1, priv, secret->base, uECC_secp256r1()))
         return PTLS_ALERT_HANDSHAKE_FAILURE;
```