# Sequence Length Signed Integer Overflow

## Classification

Denial of service, high severity.

Confidence: certain.

## Affected Locations

`asn1/tasn_enc.c:226`

## Summary

`ASN1_item_ex_i2d()` accumulates encoded child lengths for ASN.1 `SEQUENCE` values in a signed `int` without validating negative child returns or overflow. An attacker-influenced object with children whose DER lengths sum past `INT_MAX` can trigger signed integer overflow during re-encoding, invoking undefined behavior and enabling a practical process crash or optimizer-dependent miscompilation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

- An application parses attacker-controlled ASN.1 input.
- The parsed object is later re-encoded through `ASN1_item_ex_i2d()`.
- The ASN.1 item is encoded as `ASN1_ITYPE_SEQUENCE`.
- The sequence has no valid cached encoding, forcing child-length recomputation.
- Child encoded lengths are attacker-influenced and can sum beyond `INT_MAX`.

## Proof

`ASN1_item_ex_i2d()` handles `ASN1_ITYPE_SEQUENCE` by setting `seqcontlen = 0`, then iterating over `it->templates` and adding each child length returned by `asn1_template_ex_i2d(pseqval, NULL, seqtt, -1, aclass)` directly into `seqcontlen`.

Before the patch, the accumulation was:

```c
seqcontlen += asn1_template_ex_i2d(pseqval, NULL, seqtt, -1, aclass);
```

There was no check for:

- negative child return values,
- `seqcontlen + child_length > INT_MAX`,
- overflow before passing `seqcontlen` to `ASN1_object_size()`.

A reproduced path uses a decoded attacker-controlled `X509_SIG` sequence. `X509_SIG_it` contains `X509_ALGOR` and `ASN1_OCTET_STRING` children. The decoder permits primitive child content lengths below `INT_MAX`: `asn1/tasn_dec.c:420` rejects only `CBS_len(content) > INT_MAX`, and `asn1/a_string.c:184` rejects only `len >= INT_MAX`.

A DER/BER `X509_SIG` with a small `algor` child and an OCTET STRING content length of `INT_MAX - 6` makes the OCTET STRING encoded child length exactly `INT_MAX`. Adding the earlier small child length overflows signed `seqcontlen`.

## Why This Is A Real Bug

Signed integer overflow in C is undefined behavior. The overflow is reachable from attacker-controlled ASN.1 data when an application re-encodes a decoded sequence with very large child lengths.

The issue is not only a theoretical arithmetic defect: ASN.1 decoding accepts lengths large enough to construct a child whose encoded length reaches `INT_MAX`, and sequence re-encoding then adds another child length to that value without bounds checking. This can crash the process or produce optimizer-dependent behavior, which is a denial-of-service condition.

## Fix Requirement

Sequence content-length accumulation must:

- store each child encoded length separately,
- reject negative child lengths,
- reject additions that would exceed `INT_MAX`,
- only call `ASN1_object_size()` after validating the accumulated length.

## Patch Rationale

The patch adds `#include <limits.h>` so `INT_MAX` is available, introduces a temporary `tmplen`, and validates each child length before updating `seqcontlen`.

Patched logic:

```c
tmplen = asn1_template_ex_i2d(pseqval, NULL, seqtt, -1, aclass);
if (tmplen < 0 || seqcontlen > INT_MAX - tmplen)
	return 0;
seqcontlen += tmplen;
```

This prevents both error-code accumulation and signed overflow. Returning `0` is consistent with existing encoder failure behavior in this function.

## Residual Risk

None

## Patch

`020-sequence-length-signed-integer-overflow.patch`

```diff
diff --git a/asn1/tasn_enc.c b/asn1/tasn_enc.c
index a65fb5b..6fec95e 100644
--- a/asn1/tasn_enc.c
+++ b/asn1/tasn_enc.c
@@ -56,6 +56,7 @@
  *
  */
 
+#include <limits.h>
 #include <stddef.h>
 #include <string.h>
 
@@ -141,7 +142,7 @@ ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_ITEM *it,
     int tag, int aclass)
 {
 	const ASN1_TEMPLATE *tt = NULL;
-	int i, seqcontlen, seqlen, ndef = 1;
+	int i, tmplen, seqcontlen, seqlen, ndef = 1;
 	const ASN1_EXTERN_FUNCS *ef;
 	const ASN1_AUX *aux = it->funcs;
 	ASN1_aux_cb *asn1_cb = NULL;
@@ -237,9 +238,11 @@ ASN1_item_ex_i2d(ASN1_VALUE **pval, unsigned char **out, const ASN1_ITEM *it,
 			if (!seqtt)
 				return 0;
 			pseqval = asn1_get_field_ptr(pval, seqtt);
-			/* FIXME: check for errors in enhanced version */
-			seqcontlen += asn1_template_ex_i2d(pseqval, NULL, seqtt,
+			tmplen = asn1_template_ex_i2d(pseqval, NULL, seqtt,
 			    -1, aclass);
+			if (tmplen < 0 || seqcontlen > INT_MAX - tmplen)
+				return 0;
+			seqcontlen += tmplen;
 		}
 
 		seqlen = ASN1_object_size(ndef, seqcontlen, tag);
```