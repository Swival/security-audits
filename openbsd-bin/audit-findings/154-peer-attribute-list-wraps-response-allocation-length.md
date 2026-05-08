# peer attribute list wraps response allocation length

## Classification

- Certain: out-of-bounds write
- Severity: high
- Component: `isakmpd` IKE configuration attribute responder encoding

## Affected Locations

- `sbin/isakmpd/isakmp_cfg.c:776`
- `sbin/isakmpd/isakmp_cfg.c:791`
- `sbin/isakmpd/isakmp_cfg.c:795`
- `sbin/isakmpd/isakmp_cfg.c:973`

## Summary

An authenticated IKE configuration peer can send a CFG `REQUEST` containing many repeated valid attributes. The responder stores all decoded attributes without a count cap or deduplication, then computes the response allocation length in a `u_int16_t`. The 16-bit length wraps to a small value, `calloc()` allocates an undersized heap buffer, and the subsequent encode loop writes response attributes past the allocation.

## Provenance

- Reproduced from verified scanner finding.
- Source: Swival Security Scanner, https://swival.dev
- Confidence: certain

## Preconditions

- The peer can complete an authenticated IKE configuration exchange.
- The peer can send a CFG `REQUEST` with many repeated valid attributes.

## Proof

A practical trigger is an authenticated CFG `REQUEST` with 1,928 repeated basic-format `SUPPORTED_ATTRIBUTES` attributes.

- `SUPPORTED_ATTRIBUTES` type 14 is valid in `sbin/isakmpd/isakmp_num.cst:237`.
- The malicious request payload is only `8 + 1928 * 4 = 7720` bytes.
- `cfg_responder_recv_ATTR()` decodes the peer-supplied ATTRIBUTE entries into `ie->attrs` through `attribute_map()` and `cfg_decode_attribute()` without capping the list length or deduplicating repeated types.
- In `cfg_encode_attributes()`, each repeated type 14 response is assigned length 30 at `sbin/isakmpd/isakmp_cfg.c:771`.
- The vulnerable accumulator is `u_int16_t *len`; it starts at `ISAKMP_ATTRIBUTE_SZ` and adds `ISAKMP_ATTR_SZ + attr->length` for every attribute.
- For 1,928 repeated attributes, the computed response size is `8 + 1928 * (4 + 30) = 65560`.
- `65560` wraps in 16 bits to `24`, so `calloc(1, *len)` allocates only 24 bytes.
- The encode loop starts at offset 8; after encoding the first 34-byte attribute, `off` advances to 42.
- The next `SET_ISAKMP_ATTR_TYPE` / `SET_ISAKMP_ATTR_LENGTH_VALUE` at `sbin/isakmpd/isakmp_cfg.c:973` writes beyond the 24-byte heap buffer.

## Why This Is A Real Bug

The responder accepts repeated valid peer attributes and later encodes one response entry per list node. The response length calculation and the write offset are both derived from attacker-controlled attribute count, but the allocation size is truncated through 16-bit arithmetic before allocation. This creates a deterministic mismatch between the heap allocation size and the number of bytes written by the second encode loop.

Impact is deterministic heap corruption in `isakmpd` by an authenticated malicious IKE configuration peer, causing at least remote denial of service and potentially stronger memory-corruption impact.

## Fix Requirement

Use non-wrapping length arithmetic for the internal response-size calculation and reject any encoded ATTRIBUTE payload whose total length exceeds `UINT16_MAX`, since the public payload length output remains `u_int16_t`.

## Patch Rationale

The patch changes the internal size and offset arithmetic in `cfg_encode_attributes()` from `u_int16_t` to `size_t`, computes each attribute contribution as `size_t`, and checks each addition against `UINT16_MAX` before updating the total. If the payload would exceed the representable 16-bit length, encoding fails before allocation or writes occur. Only after the bounded total is finalized is it assigned back to `*len`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/isakmp_cfg.c b/sbin/isakmpd/isakmp_cfg.c
index 7c09e79..ab673c2 100644
--- a/sbin/isakmpd/isakmp_cfg.c
+++ b/sbin/isakmpd/isakmp_cfg.c
@@ -31,6 +31,7 @@
  */
 
 #include <sys/types.h>
+#include <stdint.h>
 #include <stdlib.h>
 #include <netinet/in.h>
 #include <arpa/inet.h>
@@ -739,11 +740,11 @@ cfg_encode_attributes(struct isakmp_cfg_attr_head *attrs, u_int32_t type,
 	struct sockaddr *sa;
 	sa_family_t     family;
 	u_int32_t       value;
-	u_int16_t       off;
+	size_t          attrlen, off, total;
 	char           *field;
 
 	/* Compute length */
-	*len = ISAKMP_ATTRIBUTE_SZ;
+	total = ISAKMP_ATTRIBUTE_SZ;
 	for (attr = LIST_FIRST(attrs); attr; attr = LIST_NEXT(attr, link)) {
 		/* With ACK we only include the attrs we've actually used.  */
 		if (type == ISAKMP_CFG_ACK && attr->attr_used == 0)
@@ -788,8 +789,14 @@ cfg_encode_attributes(struct isakmp_cfg_attr_head *attrs, u_int32_t type,
 			attr->ignore++;
 			/* XXX Log!  */
 		}
-		*len += ISAKMP_ATTR_SZ + attr->length;
+		attrlen = ISAKMP_ATTR_SZ + (size_t)attr->length;
+		if (attrlen > UINT16_MAX - total) {
+			log_print("cfg_encode_attributes: attribute payload too long");
+			return -1;
+		}
+		total += attrlen;
 	}
+	*len = total;
 
 	/* Allocate enough space for the payload */
 	*attrp = calloc(1, *len);
```