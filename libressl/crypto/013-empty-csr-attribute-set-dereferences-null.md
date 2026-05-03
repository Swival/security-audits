# Empty CSR Attribute Set Dereferences NULL

## Classification

denial of service, medium severity

## Affected Locations

`asn1/t_req.c:183`

## Summary

`X509_REQ_print_ex()` assumes every non-extension CSR attribute contains at least one value in `a->set`. A crafted CSR can encode a non-extension attribute with an empty values `SET`. When that CSR is printed with attributes enabled, the printer fetches element `0` from an empty stack, receives `NULL`, and immediately dereferences it via `at->type`, terminating the process.

## Provenance

Verified and reproduced from the provided finding and source review. Originally identified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- A service accepts attacker-submitted CSRs.
- The service prints or logs those CSRs using `X509_REQ_print()` or `X509_REQ_print_ex()`.
- CSR attributes are enabled, including the default `X509_REQ_print()` path.

## Proof

The CSR attribute decoder accepts an empty attribute values set:

- `asn1/x_req.c:122` defines CSR attributes as a parsed `[0] SET OF X509_ATTRIBUTE`.
- `ib.c:76` decodes an attribute value as a plain `SET OF ASN1_ANY` without a minimum-size check.
- `asn1/tasn_dec.c:1069` creates the stack.
- `asn1/tasn_dec.c:1075` skips item decoding when the SET content length is zero.
- `asn1/tasn_dec.c:1108` stores the empty stack successfully.

The printer then dereferences the missing value:

- `asn1/t_req.c:188` records `count = sk_ASN1_TYPE_num(a->set)`, which is `0`.
- `asn1/t_req.c:190` still executes `sk_ASN1_TYPE_value(a->set, ii)` with `ii == 0`.
- `stack/stack.c:333` returns `NULL` for index `0` of an empty stack.
- `asn1/t_req.c:191` immediately dereferences `at->type`.

The triggering encoded attribute uses an empty values SET, represented as `31 00`.

## Why This Is A Real Bug

The crash is reachable from attacker-controlled CSR input because decoding permits an empty attribute values SET, while printing assumes the SET has at least one element. The existing loop validates `++ii < count` only after the first dereference, so `count == 0` does not prevent the initial NULL access. A remote client can therefore terminate a CSR-printing or CSR-logging process by submitting a crafted CSR.

## Fix Requirement

Reject or skip CSR attributes whose values SET is empty before reading element `0` from `a->set`.

## Patch Rationale

The patch adds a precondition check before printing each non-extension attribute:

```c
if (sk_ASN1_TYPE_num(a->set) <= 0)
	continue;
```

This ensures `sk_ASN1_TYPE_value(a->set, 0)` is only reached when the attribute has at least one value. Skipping an unprintable empty attribute preserves printer behavior for valid attributes and avoids introducing a hard failure in diagnostic output.

## Residual Risk

None

## Patch

```diff
diff --git a/asn1/t_req.c b/asn1/t_req.c
index 51e4b4f..e547a79 100644
--- a/asn1/t_req.c
+++ b/asn1/t_req.c
@@ -181,6 +181,8 @@ X509_REQ_print_ex(BIO *bp, X509_REQ *x, unsigned long nmflags,
 				if (X509_REQ_extension_nid(
 				    OBJ_obj2nid(a->object)))
 					continue;
+				if (sk_ASN1_TYPE_num(a->set) <= 0)
+					continue;
 				if (BIO_printf(bp, "%12s", "") <= 0)
 					goto err;
 				if ((j = i2a_ASN1_OBJECT(bp, a->object)) > 0) {
```