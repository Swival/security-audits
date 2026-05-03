# Negative Key Length Writes Before Key Schedule

## Classification

High severity out-of-bounds write.

## Affected Locations

`rc2/rc2.c:117`

## Summary

`RC2_set_key()` accepts a signed `len` argument and clamps only values greater than 128. Negative values are not rejected before `len` is used as an index into the key schedule buffer. A caller-controlled negative `len` causes reads and writes before `key->data` inside the supplied writable `RC2_KEY` object.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Caller can invoke the public libcrypto API `RC2_set_key()`.
- Caller controls the `len` argument.
- Caller supplies a writable `RC2_KEY`.

## Proof

`RC2_set_key()` is public via `LCRYPTO_ALIAS(RC2_set_key)`.

The function initializes:

```c
k = (unsigned char *)&(key->data[0]);
*k = 0;
```

It then clamps only oversized lengths:

```c
if (len > 128)
	len = 128;
```

There is no `len < 0` guard. For a negative `len`:

- The copy loop is skipped because `i = 0` is not less than `len`.
- `d = k[len - 1]` reads before `key->data`.
- The expansion loop starts at `i = len`.
- For `len = -4`, the loop writes `k[-4]`, `k[-3]`, `k[-2]`, and `k[-1]` before reaching `k[0]`.

A harness with a guard buffer before `RC2_KEY` confirmed the overwrite: the final four guard bytes changed from `aa aa aa aa` to generated key-schedule bytes after calling `RC2_set_key(&key, -4, data, 1024)`.

## Why This Is A Real Bug

This is a deterministic memory safety violation in a public API. Negative `len` values are valid at the C type level because `len` is an `int`, but the implementation treats `len` as an array bound and starting index without validating the lower bound. This produces concrete out-of-bounds writes before the key schedule storage, corrupting memory adjacent to the `RC2_KEY` object.

## Fix Requirement

Reject negative `len` before any use that indexes `k` or controls writes into the key schedule.

## Patch Rationale

The patch adds an early `len < 0` check immediately after initializing the zero-length key sentinel and before any bounds-dependent use of `len`.

Returning early is safe because `k[0]` has already been set to zero, matching the existing zero-length key handling comment, and it prevents both:

- the out-of-bounds read at `k[len - 1]`
- the out-of-bounds writes from the expansion loop starting at a negative index

## Residual Risk

None

## Patch

```diff
diff --git a/rc2/rc2.c b/rc2/rc2.c
index c122d4b..7b94d82 100644
--- a/rc2/rc2.c
+++ b/rc2/rc2.c
@@ -102,6 +102,8 @@ RC2_set_key(RC2_KEY *key, int len, const unsigned char *data, int bits)
 	k = (unsigned char *)&(key->data[0]);
 	*k = 0; /* for if there is a zero length key */
 
+	if (len < 0)
+		return;
 	if (len > 128)
 		len = 128;
 	if (bits <= 0)
```