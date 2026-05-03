# UTF8 output length counter overflows

## Classification

Denial of service, medium severity.

## Affected Locations

`asn1/a_mbstr.c:352`

## Summary

`ASN1_mbstring_ncopy()` computes UTF8 output size in an `int`. During UTF8 output sizing, `out_utf8()` adds each encoded character length to `*outlen` without checking whether the addition exceeds `INT_MAX`. An attacker-controlled oversized non-ASCII input can trigger signed integer overflow before allocation and copy.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A caller accepts attacker-controlled strings large enough to exceed the `int` UTF8 output length.
- The input is converted through `ASN1_mbstring_ncopy()` to UTF8 output.
- The selected output mask permits only UTF8, for example `B_ASN1_UTF8STRING`.
- The input form can be `MBSTRING_ASC` with many non-ASCII bytes.

## Proof

A concrete trigger is a non-NULL output call with:

- `inform = MBSTRING_ASC`
- `mask = B_ASN1_UTF8STRING`
- `len = INT_MAX / 2 + 1`
- every input byte set to `0x80`

For `MBSTRING_ASC`, `traverse_string()` feeds each byte as one character to `out_utf8()`. Byte `0x80` is treated as ISO-Latin-1 and requires two bytes when encoded as UTF8. `UTF8_putc(NULL, -1, value)` therefore returns `2` for each input byte.

`out_utf8()` previously accumulated that return value with:

```c
*outlen += ret;
```

After `INT_MAX / 2 + 1` iterations, this addition exceeds `INT_MAX`, causing signed integer overflow in the `int` output length counter.

This path is reachable through direct callers of `ASN1_mbstring_ncopy()` and through higher-level conversion paths such as `ASN1_STRING_to_UTF8()` calling `ASN1_mbstring_copy(..., B_ASN1_UTF8STRING)`.

## Why This Is A Real Bug

Signed integer overflow in C is undefined behavior. Hardened builds may trap and abort, producing process denial of service. Non-hardened builds may continue with an invalid `outlen`, leading to incorrect allocation sizing and unsafe subsequent copy behavior.

The required input is large, over 1 GiB for the demonstrated two-byte expansion case, but it remains below the library’s accepted `int` length boundary and is attacker-controlled under the stated preconditions.

## Fix Requirement

Before adding `ret` to `*outlen`, verify that the addition cannot exceed `INT_MAX`. If it would overflow, return an error so `traverse_string()` fails and `ASN1_mbstring_ncopy()` exits through its existing error path.

## Patch Rationale

The patch includes `<limits.h>` to use `INT_MAX`, then adds an overflow guard in `out_utf8()`:

```c
if (*outlen > INT_MAX - ret)
	return -1;
```

This prevents undefined signed overflow while preserving existing behavior for valid inputs. Returning `-1` is consistent with other `out_utf8()` failures and is propagated by `traverse_string()` to the caller.

## Residual Risk

None

## Patch

```diff
diff --git a/asn1/a_mbstr.c b/asn1/a_mbstr.c
index 38398ad..c4f2846 100644
--- a/asn1/a_mbstr.c
+++ b/asn1/a_mbstr.c
@@ -57,6 +57,7 @@
  */
 
 #include <ctype.h>
+#include <limits.h>
 #include <stdio.h>
 #include <string.h>
 
@@ -335,6 +336,8 @@ out_utf8(unsigned long value, void *arg)
 	ret = UTF8_putc(NULL, -1, value);
 	if (ret < 0)
 		return ret;
+	if (*outlen > INT_MAX - ret)
+		return -1;
 	*outlen += ret;
 	return 1;
 }
```