# terminator byte addition overflows allocation size

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`asn1/a_mbstr.c:245`

## Summary

`ASN1_mbstring_ncopy()` stores the computed output byte count in signed `int outlen`, then allocates `malloc(outlen + 1)` for the converted string plus NUL terminator. With an `INT_MAX`-byte ASCII input converted to UTF-8, `outlen` can become exactly `INT_MAX`. The terminator addition then evaluates `INT_MAX + 1` in signed `int`, causing undefined signed integer overflow before the value is converted to `size_t`.

This can crash or destabilize a process that passes attacker-controlled large strings into this conversion path.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with the supplied source path and conversion conditions.

## Preconditions

- Caller passes an attacker-controlled string to `ASN1_mbstring_ncopy()`.
- `len == INT_MAX`.
- `inform == MBSTRING_ASC`.
- The effective mask selects UTF-8 output only, so `outform == MBSTRING_UTF8`.
- Caller does not provide a positive `maxsize` smaller than `INT_MAX`.

## Proof

For `MBSTRING_ASC`, the function sets:

```c
nchar = len;
```

With `len == INT_MAX`, `nchar == INT_MAX`.

A UTF8-only mask selects:

```c
str_type = V_ASN1_UTF8STRING;
outform = MBSTRING_UTF8;
```

Because `inform != outform`, the conversion sizing path runs:

```c
outlen = 0;
if (traverse_string(in, len, inform, out_utf8, &outlen) < 0) {
	...
}
```

For ASCII input, each byte is one UTF-8 byte. `out_utf8()` adds one per character:

```c
ret = UTF8_putc(NULL, -1, value);
*outlen += ret;
```

After traversing `INT_MAX` ASCII bytes, `outlen == INT_MAX`.

The allocation then evaluates:

```c
malloc(outlen + 1)
```

Since `outlen` is signed `int`, `INT_MAX + 1` is undefined behavior before conversion to `size_t`. The reproduced runtime check triggers a UBSan signed-overflow abort at this expression.

## Why This Is A Real Bug

The overflow occurs before the allocation failure check can handle the condition. It is not merely an oversized allocation failure; the C expression itself has undefined behavior.

`ASN1_mbstring_ncopy()` does not independently reject `len == INT_MAX` for this path. `maxsize` only prevents the bug when the caller supplies a positive cap. UTF8-only masks are valid inputs and can be reached through public callers. Therefore a remote attacker can trigger a process crash or other undefined behavior if an application feeds a sufficiently large client-controlled string into this conversion.

## Fix Requirement

The code must prevent the terminator-byte addition from overflowing signed `int`.

Acceptable fixes include:

- reject `outlen >= INT_MAX` before evaluating `outlen + 1`;
- or convert output sizing to checked `size_t` arithmetic and verify all additions.

## Patch Rationale

The patch includes `<limits.h>` for `INT_MAX` and rejects `outlen >= INT_MAX` before `malloc(outlen + 1)` is evaluated:

```c
if (outlen >= INT_MAX || !(p = malloc(outlen + 1))) {
```

This preserves existing behavior for valid smaller outputs while preventing the exact overflow case where adding the terminator would exceed signed `int`.

Using `>= INT_MAX` is appropriate because `outlen == INT_MAX` cannot safely add one terminator byte in an `int` expression.

## Residual Risk

None

## Patch

```diff
diff --git a/asn1/a_mbstr.c b/asn1/a_mbstr.c
index 38398ad..170a4b1 100644
--- a/asn1/a_mbstr.c
+++ b/asn1/a_mbstr.c
@@ -57,6 +57,7 @@
  */
 
 #include <ctype.h>
+#include <limits.h>
 #include <stdio.h>
 #include <string.h>
 
@@ -239,7 +240,7 @@ ASN1_mbstring_ncopy(ASN1_STRING **out, const unsigned char *in, int len,
 		cpyfunc = cpy_utf8;
 		break;
 	}
-	if (!(p = malloc(outlen + 1))) {
+	if (outlen >= INT_MAX || !(p = malloc(outlen + 1))) {
 		ASN1error(ERR_R_MALLOC_FAILURE);
 		goto err;
 	}
```