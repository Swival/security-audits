# Zero-Length GCM Tag Authenticates Successfully

## Classification

High severity security control failure.

## Affected Locations

`modes/gcm128.c:569`

## Summary

`CRYPTO_gcm128_finish()` accepted a non-NULL authentication tag with `len == 0`. The function then called `timingsafe_memcmp(ctx->Xi.c, tag, len)`, and a zero-length comparison returned `0`, which is the verifier success value. A caller that allowed a peer-controlled zero tag length could therefore accept forged GCM ciphertext without validating any tag bytes.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A caller must:

- Use the exported low-level `CRYPTO_gcm128_finish()` verifier directly.
- Accept an attacker- or peer-controlled GCM tag length.
- Treat return value `0` from `CRYPTO_gcm128_finish()` as authentication success.
- Pass a non-NULL tag pointer with `len == 0`.

## Proof

`CRYPTO_gcm128_finish()` computes the final GCM authenticator into `ctx->Xi`, then validates the caller-supplied tag.

Before the patch:

```c
if (tag == NULL || len > sizeof(ctx->Xi))
	return -1;

return timingsafe_memcmp(ctx->Xi.c, tag, len);
```

This rejected only a NULL tag pointer or an oversized tag. It did not reject `len == 0`.

For a non-NULL pointer and `len == 0`, execution reached:

```c
timingsafe_memcmp(ctx->Xi.c, tag, len)
```

A zero-length comparison compares no bytes and returns `0`. In this API, `0` means authentication success; callers such as EVP GCM code paths treat `CRYPTO_gcm128_finish(...) != 0` as failure. Therefore a zero-length tag authenticated successfully regardless of the computed GCM tag.

## Why This Is A Real Bug

GCM authentication depends on comparing at least one byte of the computed authentication tag against the supplied tag. Accepting `len == 0` means no authentication material is checked.

The low-level function is exported and implements the authentication tag verifier itself. Even if higher-level EVP controls reject zero-length GCM tags, the verifier’s own contract was unsafe for direct callers that pass peer-controlled tag lengths. Under the stated preconditions, forged ciphertext can be accepted without a valid tag.

## Fix Requirement

Reject zero-length tags before comparing the computed GCM authenticator with the supplied tag.

## Patch Rationale

The patch adds `len == 0` to the existing invalid-input guard:

```c
if (tag == NULL || len == 0 || len > sizeof(ctx->Xi))
	return -1;
```

This preserves the existing behavior for NULL tags and oversized tags while ensuring the verifier cannot report success without comparing any authentication bytes.

## Residual Risk

None

## Patch

```diff
diff --git a/modes/gcm128.c b/modes/gcm128.c
index a88f589..53f038b 100644
--- a/modes/gcm128.c
+++ b/modes/gcm128.c
@@ -568,7 +568,7 @@ CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
 	ctx->Xi.u[0] ^= ctx->EK0.u[0];
 	ctx->Xi.u[1] ^= ctx->EK0.u[1];
 
-	if (tag == NULL || len > sizeof(ctx->Xi))
+	if (tag == NULL || len == 0 || len > sizeof(ctx->Xi))
 		return -1;
 
 	return timingsafe_memcmp(ctx->Xi.c, tag, len);
```