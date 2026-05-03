# set-of length signed integer overflow

## Classification

High severity denial of service.

Confidence: certain.

## Affected Locations

`asn1/tasn_enc.c:324`

## Summary

ASN.1 SET OF / SEQUENCE OF re-encoding summed attacker-influenced member DER lengths into a signed `int` without overflow checks. If the aggregate encoded member length exceeded `INT_MAX`, `skcontlen += ASN1_item_ex_i2d(...)` invoked signed-integer-overflow undefined behavior before object-size calculation or allocation, allowing a remote attacker to crash trapping/sanitized builds or trigger compiler-dependent misbehavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The application parses attacker-controlled ASN.1 data.
- The application later re-encodes attacker-controlled ASN.1 SET OF or SEQUENCE OF values.
- The parsed collection contains multiple individually valid members whose encoded lengths sum beyond `INT_MAX`.

## Proof

The vulnerable path is in `asn1_template_ex_i2d()` for `ASN1_TFLG_SK_MASK`.

Before the patch, the encoder used:

```c
int skcontlen;

skcontlen = 0;
for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
	skitem = sk_ASN1_VALUE_value(sk, i);
	skcontlen += ASN1_item_ex_i2d(&skitem, NULL,
	    tt->item, -1, iclass);
}
```

A concrete reproduced trigger is a 64-bit process parsing and re-encoding a SET containing two OCTET STRING members with content length `0x3ffffffc`.

Each member encodes to length `0x40000002`. The first addition stores `0x40000002`; the second attempts to compute `0x80000004`, which exceeds `INT_MAX` and overflows signed `int`.

The overflow occurs before:

```c
sklen = ASN1_object_size(ndef, skcontlen, sktag);
```

so later object-size or allocation logic cannot prevent the undefined behavior.

## Why This Is A Real Bug

The decoder can accept the required input shape:

- SET OF aggregate length is tracked as `size_t` and is not capped at `INT_MAX` before building the stack.
- Individual primitive members are rejected only when their own content length exceeds `INT_MAX`.
- Two individually valid large OCTET STRING members can therefore be stored after parsing.
- Re-encoding sums their encoded lengths into signed `int skcontlen` with no overflow check.

Signed integer overflow in C is undefined behavior. This is attacker-reachable during normal re-encoding of peer-controlled ASN.1 and can produce denial of service, especially in sanitized, trapping, or optimization-sensitive builds.

## Fix Requirement

The SET OF / SEQUENCE OF aggregate length must be accumulated in an unsigned size type with explicit overflow checks, and lengths that cannot be represented as `int` must be rejected before calling APIs that take `int` lengths.

## Patch Rationale

The patch:

- Includes `<limits.h>` for `INT_MAX`.
- Accumulates the aggregate member length in `size_t skcontlen_size`.
- Stores each member length in `int skitemlen`.
- Rejects negative member-encoding results.
- Checks `skcontlen_size > (size_t)INT_MAX - (size_t)skitemlen` before addition.
- Converts to `int skcontlen` only after proving the value is representable.

This removes the signed-overflow operation while preserving the existing downstream `int`-based interfaces.

## Residual Risk

None

## Patch

```diff
diff --git a/asn1/tasn_enc.c b/asn1/tasn_enc.c
index a65fb5b..2879c47 100644
--- a/asn1/tasn_enc.c
+++ b/asn1/tasn_enc.c
@@ -56,6 +56,7 @@
  *
  */
 
+#include <limits.h>
 #include <stddef.h>
 #include <string.h>
 
@@ -319,7 +320,8 @@ asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
 		/* SET OF, SEQUENCE OF */
 		STACK_OF(ASN1_VALUE) *sk = (STACK_OF(ASN1_VALUE) *)*pval;
 		int isset, sktag, skaclass;
-		int skcontlen, sklen;
+		int skcontlen, skitemlen, sklen;
+		size_t skcontlen_size;
 		ASN1_VALUE *skitem;
 
 		if (!*pval)
@@ -348,12 +350,20 @@ asn1_template_ex_i2d(ASN1_VALUE **pval, unsigned char **out,
 		}
 
 		/* Determine total length of items */
-		skcontlen = 0;
+		skcontlen_size = 0;
 		for (i = 0; i < sk_ASN1_VALUE_num(sk); i++) {
 			skitem = sk_ASN1_VALUE_value(sk, i);
-			skcontlen += ASN1_item_ex_i2d(&skitem, NULL,
-			    tt->item, -1, iclass);
+			if ((skitemlen = ASN1_item_ex_i2d(&skitem, NULL,
+			    tt->item, -1, iclass)) < 0)
+				return -1;
+			if (skcontlen_size > (size_t)INT_MAX -
+			    (size_t)skitemlen) {
+				ASN1error(ASN1_R_LENGTH_ERROR);
+				return -1;
+			}
+			skcontlen_size += skitemlen;
 		}
+		skcontlen = (int)skcontlen_size;
 		sklen = ASN1_object_size(ndef, skcontlen, sktag);
 		/* If EXPLICIT need length of surrounding tag */
 		if (flags & ASN1_TFLG_EXPTAG)
```