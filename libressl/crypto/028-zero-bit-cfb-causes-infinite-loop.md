# Zero-Bit CFB Causes Infinite Loop

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`des/des.c:229`

## Summary

`DES_ede3_cfb_encrypt()` accepts `numbits == 0`. This makes the computed byte step `n` equal zero, so both encryption and decryption loops execute with `while (l >= n)` and never reduce `l`, `in`, or `out`. A caller that supplies positive `length` and zero `numbits` can pin the caller thread indefinitely.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced against the committed source and confirmed as a triggerable infinite loop.

## Preconditions

- Caller invokes public API `DES_ede3_cfb_encrypt()`.
- `length` is positive.
- `numbits` is zero.
- Other arguments are valid enough for the function to enter its CFB loop.

## Proof

In `DES_ede3_cfb_encrypt()`:

- `des/des.c:217` computes `n = ((unsigned int)numbits + 7) / 8`.
- With `numbits == 0`, `n == 0`.
- `des/des.c:223` only rejects `num > 64`, so zero is accepted.
- `des/des.c:229` and `des/des.c:271` use `while (l >= n)`.
- With `n == 0`, `l >= n` is always true for nonnegative `l`.
- `des/des.c:230` and `des/des.c:272` execute `l -= n`, which subtracts zero.
- `in += n` and `out += n` also make no progress.
- The zero-length `c2ln` and `l2cn` paths do not consume input or write output.

The function therefore repeatedly performs DES work and state updates without termination.

## Why This Is A Real Bug

The API exposes `numbits` as caller-controlled input, and the implementation already attempts to validate the upper bound. However, it omits the lower bound check present in the related single-DES CFB implementation, which rejects `numbits <= 0`.

Because `n == 0` prevents loop progress, this is not a theoretical edge case or undefined behavior dependency. It is a deterministic infinite loop reachable with valid pointers, schedules, positive length, and `numbits == 0`.

## Fix Requirement

Reject `numbits <= 0` before computing or using the byte step `n`.

## Patch Rationale

The patch changes `n` from an initializer-time computation to a post-validation assignment and extends validation from:

```c
if (num > 64)
	return;
```

to:

```c
if (num <= 0 || num > 64)
	return;
n = ((unsigned int)numbits + 7)/8;
```

This guarantees `n` is at least one before either `while (l >= n)` loop can execute. It also aligns `DES_ede3_cfb_encrypt()` with `DES_cfb_encrypt()`, which already rejects `numbits <= 0 || numbits > 64`.

## Residual Risk

None

## Patch

```diff
diff --git a/des/des.c b/des/des.c
index 113fc4b..78f5940 100644
--- a/des/des.c
+++ b/des/des.c
@@ -214,14 +214,15 @@ DES_ede3_cfb_encrypt(const unsigned char *in, unsigned char *out,
     DES_cblock *ivec, int enc)
 {
 	DES_LONG d0, d1, v0, v1;
-	unsigned long l = length, n = ((unsigned int)numbits + 7)/8;
+	unsigned long l = length, n;
 	int num = numbits, i;
 	DES_LONG ti[2];
 	unsigned char *iv;
 	unsigned char ovec[16];
 
-	if (num > 64)
+	if (num <= 0 || num > 64)
 		return;
+	n = ((unsigned int)numbits + 7)/8;
 	iv = &(*ivec)[0];
 	c2l(iv, v0);
 	c2l(iv, v1);
```