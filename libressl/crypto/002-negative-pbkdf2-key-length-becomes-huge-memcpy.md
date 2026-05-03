# Negative PBKDF2 Key Length Becomes Huge Memcpy

## Classification

High severity out-of-bounds write.

## Affected Locations

`evp/evp_pbe.c:378`

## Summary

`PKCS5_PBKDF2_HMAC()` accepts a public `int keylen` and copies it into `tkeylen` without rejecting negative values. A negative `keylen` makes the PBKDF2 loop execute with a negative `cplen`, which is then passed to `memcpy()` and converted to a huge `size_t`. This can corrupt memory in the caller process when an application exposes PBKDF2 output length to attacker-controlled input.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A caller exposes attacker-controlled `keylen` to `PKCS5_PBKDF2_HMAC()` or `PKCS5_PBKDF2_HMAC_SHA1()`.
- Other PBKDF2 inputs are valid enough for setup to succeed, such as valid password, salt, digest, and positive iteration count.

## Proof

`PKCS5_PBKDF2_HMAC()` is public, and `PKCS5_PBKDF2_HMAC_SHA1()` forwards `keylen` unchanged to it.

A trigger such as:

```c
PKCS5_PBKDF2_HMAC_SHA1("p", 1, salt, 1, 1, -1, out);
```

reaches the vulnerable path:

- `keylen == -1` is assigned directly to `tkeylen`.
- `while (tkeylen)` is true for `-1`.
- `tkeylen > mdlen` is false, so `cplen = tkeylen`, making `cplen == -1`.
- `memcpy(p, digtmp, cplen)` converts `-1` to a huge `size_t`.
- `p` points to caller-provided `out`.
- `digtmp` is a fixed `EVP_MAX_MD_SIZE` stack buffer.

The result is an oversized copy from a small stack buffer into caller-controlled output storage, producing out-of-bounds read and out-of-bounds write before return. A minimal ASan harness for this data flow reports `negative-size-param` at the `memcpy()`.

## Why This Is A Real Bug

The vulnerable argument is public API input, not an internal invariant. Negative `keylen` values are representable by the declared `int` type and are not rejected before arithmetic and memory-copy length selection. C converts the negative `int cplen` to an unsigned `size_t` for `memcpy()`, turning a small negative value into a very large copy length. This is direct memory corruption in the caller process under the stated precondition.

## Fix Requirement

Reject `keylen <= 0` before assigning it to `tkeylen` or using it to compute `cplen`.

## Patch Rationale

The patch extends the existing early validation after `EVP_MD_size()`:

```diff
-	if (mdlen < 0)
+	if (mdlen < 0 || keylen <= 0)
 		return 0;
```

This prevents negative and zero output lengths from entering the PBKDF2 loop. For the reproduced negative case, the function now returns failure before `tkeylen = keylen`, before `while (tkeylen)`, and before the dangerous `memcpy()`.

## Residual Risk

None

## Patch

```diff
diff --git a/evp/evp_pbe.c b/evp/evp_pbe.c
index cb2ace1..9fc4f74 100644
--- a/evp/evp_pbe.c
+++ b/evp/evp_pbe.c
@@ -336,7 +336,7 @@ PKCS5_PBKDF2_HMAC(const char *pass, int passlen, const unsigned char *salt,
 	HMAC_CTX hctx_tpl, hctx;
 
 	mdlen = EVP_MD_size(digest);
-	if (mdlen < 0)
+	if (mdlen < 0 || keylen <= 0)
 		return 0;
 
 	HMAC_CTX_init(&hctx_tpl);
```