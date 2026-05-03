# unchecked CFB state indexes past IV

## Classification

High severity out-of-bounds write.

## Affected Locations

`modes/cfb128.c:75`

## Summary

`CRYPTO_cfb128_encrypt()` copied caller-controlled `*num` into unsigned state variable `n` and used `n` as an IV index before constraining it to the 16-byte CFB block size. With `len > 0`, `num = 16` immediately accessed `ivec[16]`, one byte past the IV. Negative `*num` values converted to very large unsigned indexes.

The patch normalizes `*num` to `0..15` before any `ivec[n]` access.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller controls `num`.
- Caller passes `len > 0`.
- Caller invokes the public CFB API path, directly or through a wrapper such as `AES_cfb128_encrypt`.

## Proof

`CRYPTO_cfb128_encrypt()` initialized state with:

```c
n = *num;
```

In encryption mode, when `n != 0` and `len > 0`, execution entered:

```c
while (n && len) {
	*(out++) = ivec[n] ^= *(in++);
	--len;
	n = (n + 1) % 16;
}
```

The access to `ivec[n]` occurred before `n` was normalized with `% 16`.

In decryption mode, the same pre-normalization pattern occurred:

```c
while (n && len) {
	unsigned char c;
	*(out++) = ivec[n] ^ (c = *(in++));
	ivec[n] = c;
	--len;
	n = (n + 1) % 16;
}
```

A minimal trigger is:

- `num = 16`
- `len = 1`
- caller-supplied IV followed by adjacent process data

In decrypt mode, the first ciphertext byte is written to `ivec[16]`, and `out[0]` contains the old adjacent byte XOR the attacker-controlled ciphertext byte. This provides both adjacent memory overwrite and adjacent memory disclosure in output.

## Why This Is A Real Bug

`ivec` is a 16-byte buffer, so valid indexes are `0..15`. The function accepted `*num` without validation, converted it to `unsigned int`, and used it directly as an array index.

The API is public/exported via `modes/modes.h:53` and `Symbols.list:620`. Wrappers such as `AES_cfb128_encrypt` pass the caller's `num` through unchanged at `aes/aes.c:177`, so an untrusted library consumer can reach the vulnerable code path.

Because the out-of-bounds access happens before the existing modulo operation, the later normalization does not prevent the memory corruption or disclosure.

## Fix Requirement

Reject or normalize `*num` to `0..15` before any `ivec[n]` indexing.

## Patch Rationale

The patch changes initialization from:

```c
n = *num;
```

to:

```c
n = (unsigned int)*num % 16;
```

This guarantees `n` is in the valid IV index range before either encryption or decryption loops can access `ivec[n]`. It also handles negative `*num` values by converting to unsigned and reducing modulo 16 before use.

The change preserves the function's existing modulo-based state behavior while moving the normalization before the first memory access.

## Residual Risk

None

## Patch

```diff
diff --git a/modes/cfb128.c b/modes/cfb128.c
index 9a63a46..c869733 100644
--- a/modes/cfb128.c
+++ b/modes/cfb128.c
@@ -68,7 +68,7 @@ CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
 	unsigned int n;
 	size_t l = 0;
 
-	n = *num;
+	n = (unsigned int)*num % 16;
 
 	if (enc) {
 		if (16 % sizeof(size_t) == 0)
```