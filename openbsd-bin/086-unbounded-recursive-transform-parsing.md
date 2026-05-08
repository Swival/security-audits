# Unbounded Recursive Transform Parsing

## Classification

High severity denial of service.

Confidence: certain.

## Affected Locations

`sbin/iked/ikev2_pld.c:541`

## Summary

`ikev2_pld_xform()` parsed IKEv2 SA proposal transforms recursively. An unauthenticated remote IKE peer could send an SA payload containing many valid minimal transforms with `xfrm_more == IKEV2_XFORM_MORE`, causing recursion depth proportional to attacker-controlled payload size. Each recursive frame allocated `char id[BUFSIZ]`, making a max-sized SA payload sufficient to exhaust the daemon stack and deny IKE service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Peer message reaches SA payload parsing before authentication.
- Attacker controls an IKEv2 SA payload containing many transform substructures.
- Each transform has a valid length and sets `xfrm_more` to request another transform.

## Proof

The reproduced path is:

- `ikev2_pld_payloads()` dispatches attacker-supplied `IKEV2_PAYLOAD_SA` to `ikev2_pld_sa()`.
- `ikev2_pld_sa()` treats `sap_transforms` as a boolean and calls `ikev2_pld_xform()` with the proposal transform byte count.
- `ikev2_pld_xform()` validates and consumes one transform, then recurses when `xfrm.xfrm_more == IKEV2_XFORM_MORE`.
- Every recursive frame contains `char id[BUFSIZ]`, so stack consumption grows linearly with transform count.
- A max-sized SA payload can encode 8,190 minimal 8-byte transforms: `4 + 8 + 8190 * 8 = 65532`.
- 8,190 nested frames are enough to exhaust the normal finite `iked` child stack.
- A stack fault kills the `iked` child; the parent treats child signal death as fatal and shuts down `iked`.

The reproducer confirmed this as service DoS before authentication-sensitive proposal storage.

## Why This Is A Real Bug

The input is remotely attacker controlled and reaches SA parsing before authentication. The parser accepts each minimal transform as structurally valid and uses `xfrm_more` to drive unbounded recursive calls. The maximum IKE payload size still permits thousands of nested calls, and each call reserves a `BUFSIZ` stack buffer, making stack exhaustion practical rather than theoretical.

## Fix Requirement

Parse transforms iteratively instead of recursively, and enforce the transform count declared by the SA proposal. Reject payloads that contain more transform entries than declared, fewer bytes than required, or trailing transform data after parsing terminates.

## Patch Rationale

The patch changes `ikev2_pld_xform()` to accept `sap.sap_transforms` as an explicit count and iterates over at most that many transforms. This removes attacker-controlled recursion and binds parsing to the protocol-declared transform count.

The patch also preserves existing per-transform validation, attribute parsing, logging, and transform registration behavior. It rejects inconsistent encodings by returning an error when unconsumed transform bytes remain or when the transform chain still advertises `IKEV2_XFORM_MORE` after the declared count is exhausted.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/ikev2_pld.c b/sbin/iked/ikev2_pld.c
index 378fdaf..5c1f390 100644
--- a/sbin/iked/ikev2_pld.c
+++ b/sbin/iked/ikev2_pld.c
@@ -54,7 +54,7 @@ int	 ikev2_pld_sa(struct iked *, struct ikev2_payload *,
 int	 ikev2_validate_xform(struct iked_message *, size_t, size_t,
 	    struct ikev2_transform *);
 int	 ikev2_pld_xform(struct iked *, struct iked_message *,
-	    size_t, size_t);
+	    size_t, size_t, unsigned int);
 int	 ikev2_validate_attr(struct iked_message *, size_t, size_t,
 	    struct ikev2_attribute *);
 int	 ikev2_pld_attr(struct iked *, struct ikev2_transform *,
@@ -435,7 +435,8 @@ ikev2_pld_sa(struct iked *env, struct ikev2_payload *pld,
 		 * Parse the attached transforms
 		 */
 		if (sap.sap_transforms) {
-			r = ikev2_pld_xform(env, msg, offset, total);
+			r = ikev2_pld_xform(env, msg, offset, total,
+			    sap.sap_transforms);
 			if ((r == -2) && ikev2_msg_frompeer(msg)) {
 				log_debug("%s: invalid proposal transform",
 				    __func__);
@@ -488,89 +489,99 @@ ikev2_validate_xform(struct iked_message *msg, size_t offset, size_t total,
 
 int
 ikev2_pld_xform(struct iked *env, struct iked_message *msg,
-    size_t offset, size_t total)
+    size_t offset, size_t total, unsigned int count)
 {
 	struct ikev2_transform		 xfrm;
 	char				 id[BUFSIZ];
-	int				 ret = 0;
 	int				 r;
 	size_t				 xfrm_length;
+	unsigned int			 i;
 
-	if (ikev2_validate_xform(msg, offset, total, &xfrm))
+	if (count == 0)
 		return (-1);
 
-	xfrm_length = betoh16(xfrm.xfrm_length);
-
-	switch (xfrm.xfrm_type) {
-	case IKEV2_XFORMTYPE_ENCR:
-		strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
-		    ikev2_xformencr_map), sizeof(id));
-		break;
-	case IKEV2_XFORMTYPE_PRF:
-		strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
-		    ikev2_xformprf_map), sizeof(id));
-		break;
-	case IKEV2_XFORMTYPE_INTEGR:
-		strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
-		    ikev2_xformauth_map), sizeof(id));
-		break;
-	case IKEV2_XFORMTYPE_DH:
-		strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
-		    ikev2_xformdh_map), sizeof(id));
-		break;
-	case IKEV2_XFORMTYPE_ESN:
-		strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
-		    ikev2_xformesn_map), sizeof(id));
-		break;
-	default:
-		snprintf(id, sizeof(id), "<%d>", betoh16(xfrm.xfrm_id));
-		break;
-	}
-
-	log_debug("%s: more %d reserved %d length %zu"
-	    " type %s id %s",
-	    __func__, xfrm.xfrm_more, xfrm.xfrm_reserved, xfrm_length,
-	    print_map(xfrm.xfrm_type, ikev2_xformtype_map), id);
-
-	/*
-	 * Parse transform attributes, if available
-	 */
-	msg->msg_attrlength = 0;
-	if (xfrm_length > sizeof(xfrm)) {
-		if (ikev2_pld_attr(env, &xfrm, msg, offset + sizeof(xfrm),
-		    xfrm_length - sizeof(xfrm)) != 0) {
+	for (i = 0; i < count; i++) {
+		if (ikev2_validate_xform(msg, offset, total, &xfrm))
 			return (-1);
+
+		xfrm_length = betoh16(xfrm.xfrm_length);
+
+		switch (xfrm.xfrm_type) {
+		case IKEV2_XFORMTYPE_ENCR:
+			strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
+			    ikev2_xformencr_map), sizeof(id));
+			break;
+		case IKEV2_XFORMTYPE_PRF:
+			strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
+			    ikev2_xformprf_map), sizeof(id));
+			break;
+		case IKEV2_XFORMTYPE_INTEGR:
+			strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
+			    ikev2_xformauth_map), sizeof(id));
+			break;
+		case IKEV2_XFORMTYPE_DH:
+			strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
+			    ikev2_xformdh_map), sizeof(id));
+			break;
+		case IKEV2_XFORMTYPE_ESN:
+			strlcpy(id, print_map(betoh16(xfrm.xfrm_id),
+			    ikev2_xformesn_map), sizeof(id));
+			break;
+		default:
+			snprintf(id, sizeof(id), "<%d>", betoh16(xfrm.xfrm_id));
+			break;
 		}
+
+		log_debug("%s: more %d reserved %d length %zu"
+		    " type %s id %s",
+		    __func__, xfrm.xfrm_more, xfrm.xfrm_reserved, xfrm_length,
+		    print_map(xfrm.xfrm_type, ikev2_xformtype_map), id);
+
+		/*
+		 * Parse transform attributes, if available
+		 */
+		msg->msg_attrlength = 0;
+		if (xfrm_length > sizeof(xfrm)) {
+			if (ikev2_pld_attr(env, &xfrm, msg, offset + sizeof(xfrm),
+			    xfrm_length - sizeof(xfrm)) != 0) {
+				return (-1);
+			}
+		}
+
+		if (ikev2_msg_frompeer(msg)) {
+			r = config_add_transform(msg->msg_parent->msg_prop,
+			    xfrm.xfrm_type, betoh16(xfrm.xfrm_id),
+			    msg->msg_attrlength, msg->msg_attrlength);
+			if (r == -1) {
+				log_debug("%s: failed to add transform: alloc error",
+				    __func__);
+				return (r);
+			} else if (r == -2) {
+				log_debug("%s: failed to add transform: unknown type",
+				    __func__);
+				return (r);
+			}
+		}
+
+		/* Next transform */
+		offset += xfrm_length;
+		total -= xfrm_length;
+		if (xfrm.xfrm_more != IKEV2_XFORM_MORE)
+			break;
 	}
 
-	if (ikev2_msg_frompeer(msg)) {
-		r = config_add_transform(msg->msg_parent->msg_prop,
-		    xfrm.xfrm_type, betoh16(xfrm.xfrm_id),
-		    msg->msg_attrlength, msg->msg_attrlength);
-		if (r == -1) {
-			log_debug("%s: failed to add transform: alloc error",
-			    __func__);
-			return (r);
-		} else if (r == -2) {
-			log_debug("%s: failed to add transform: unknown type",
-			    __func__);
-			return (r);
-		}
-	}
-
-	/* Next transform */
-	offset += xfrm_length;
-	total -= xfrm_length;
-	if (xfrm.xfrm_more == IKEV2_XFORM_MORE)
-		ret = ikev2_pld_xform(env, msg, offset, total);
-	else if (total != 0) {
+	if (total != 0) {
 		/* No more transforms but still some data left. */
 		log_debug("%s: less data than specified, %zu bytes left",
 		    __func__, total);
-		ret = -1;
+		return (-1);
+	}
+	if (i == count && xfrm.xfrm_more == IKEV2_XFORM_MORE) {
+		log_debug("%s: too many transforms", __func__);
+		return (-1);
 	}
 
-	return (ret);
+	return (0);
 }
 
 int
```