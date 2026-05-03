# Out-of-range OFB num leaks stack byte

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`rc2/rc2.c:444`

## Summary

`RC2_ofb64_encrypt()` trusts caller-controlled `*num` as an index into the 8-byte local buffer `d`. If a caller passes `*num` outside `0..7` and requests at least one output byte, the first loop iteration reads `d[n]` before `n` is normalized. The leaked stack byte is XORed into attacker-observable output.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller can invoke the exported low-level libcrypto API `RC2_ofb64_encrypt()`.
- Caller controls `*num`.
- Caller requests `length > 0`.
- Caller can observe the output buffer.
- For direct disclosure of the read byte, caller uses a known input byte such as `0x00`.

## Proof

`RC2_ofb64_encrypt()` copies `*num` into `n`:

```c
int n = *num;
```

It initializes only the local 8-byte buffer `d[0..7]`:

```c
unsigned char d[8];
...
l2c(v0, dp);
l2c(v1, dp);
```

The loop then indexes `d[n]` before constraining `n`:

```c
*(out++) = *(in++) ^ d[n];
n = (n + 1) & 0x07;
```

With `*num = 8`, `length = 1`, and input byte `0x00`, the first output byte becomes `d[8]`, an out-of-bounds stack byte immediately past `d`.

A small ASan harness using `num = 8` and `length = 1` reproduced a `stack-buffer-overflow` read of size 1 in `RC2_ofb64_encrypt()` at the `d[n]` access, immediately past local stack buffer `d`.

## Why This Is A Real Bug

`RC2_ofb64_encrypt()` is an exported low-level API. Although the normal EVP wrapper initializes and maintains `ctx->num`, the low-level API accepts an external `int *num` and performs no validation before the first buffer access. The post-access normalization cannot protect the first iteration, so invalid caller state directly causes an out-of-bounds stack read and data-dependent observable output.

## Fix Requirement

Constrain `*num` to the valid OFB byte offset range `0..7` before any use as an index into `d`.

## Patch Rationale

The patch masks `*num` when initializing `n`:

```c
int n = *num & 0x07;
```

This preserves the existing modulo-8 OFB state semantics while ensuring every access to `d[n]` is within `d[0..7]`, including the first loop iteration. The existing loop increment already uses the same mask, so the change is consistent with the function’s state progression.

## Residual Risk

None

## Patch

```diff
diff --git a/rc2/rc2.c b/rc2/rc2.c
index c122d4b..c5f9156 100644
--- a/rc2/rc2.c
+++ b/rc2/rc2.c
@@ -419,7 +419,7 @@ RC2_ofb64_encrypt(const unsigned char *in, unsigned char *out,
     int *num)
 {
 	unsigned long v0, v1, t;
-	int n = *num;
+	int n = *num & 0x07;
 	long l = length;
 	unsigned char d[8];
 	char *dp;
```