# CHECK CONDITION sense length out-of-bounds read

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`usr.sbin/iscsid/vscsi.c:244`

## Summary

`iscsid` accepts target-controlled `ISCSI_OP_SCSI_RESPONSE` PDUs. For `ISCSI_SCSI_STAT_CHCK_COND`, `vscsi_callback()` retrieves the PDU data segment and decodes the two-byte sense length without first requiring that at least two bytes were received. A malicious iSCSI target can send a CHECK CONDITION response with a one-byte data segment, causing later sense-data handling to read past the received PDU data buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- An `iscsid` session receives a SCSI response from a target.
- The response opcode is `ISCSI_OP_SCSI_RESPONSE`.
- The response status is `ISCSI_SCSI_STAT_CHCK_COND`.
- The target supplies a PDU data segment shorter than the required two-byte sense-length field, specifically a one-byte segment for the reproduced crash path.

## Proof

In `vscsi_callback()`, CHECK CONDITION handling does:

```c
buf = pdu_getbuf(p, &n, PDU_DATA);
if (buf) {
	size = buf[0] << 8 | buf[1];
	buf += 2;
}
```

The code checks only that `buf` is non-NULL. It does not check `n >= 2` before reading `buf[0]` and `buf[1]`, and it does not verify that the decoded sense length fits inside the received data segment before passing the adjusted pointer to `vscsi_status()`.

The reproduced path uses a CHECK CONDITION response with `DataSegmentLength` 1. `pdu_getbuf()` returns a non-NULL data pointer and records `n == 1`. With the first byte set to `0xff`, `size = buf[0] << 8 | buf[1]` produces an attacker-influenced length while the buffer is still undersized. After `buf += 2`, the source pointer is beyond the one-byte logical data segment.

`vscsi_status()` then caps only the destination length to `sizeof(t2i.sense)` before copying:

```c
if (len > sizeof(t2i.sense))
	len = sizeof(t2i.sense);
memcpy(&t2i.sense, buf, len);
```

An equivalent ASan harness for these code paths aborts with a heap-buffer-overflow when `vscsi_status()` copies 18 bytes from a 4-byte PDU allocation at offset 2.

## Why This Is A Real Bug

The PDU data segment is controlled by the iSCSI target. The CHECK CONDITION parser assumes the segment contains at least the two-byte sense-length field and then trusts the decoded length for a later `memcpy()` source read. A one-byte segment is sufficient to reach a concrete heap out-of-bounds read in the reproduced harness.

Although a zero-length segment is blocked by `buf == NULL`, the one-byte segment remains valid for reaching the vulnerable path. The destination bound in `vscsi_status()` does not protect the source buffer.

## Fix Requirement

Require the CHECK CONDITION data segment to contain at least the two-byte sense-length field before decoding it. If the data segment is absent or shorter than two bytes, reject the response and fail the connection instead of calling `vscsi_status()` with attacker-derived sense data.

## Patch Rationale

The patch changes CHECK CONDITION handling to reject malformed sense data early:

```c
if (buf == NULL || n < 2) {
	log_debug("vscsi_callback: bad scsi response");
	conn_fail(c);
	goto done;
}
```

Only after this validation does the code decode the two-byte sense length and advance the buffer pointer. The added `done:` label ensures the PDU is still freed on the early rejection path.

This directly prevents the reproduced one-byte data segment from reaching the out-of-bounds read path.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/iscsid/vscsi.c b/usr.sbin/iscsid/vscsi.c
index c19b50c..9f79510 100644
--- a/usr.sbin/iscsid/vscsi.c
+++ b/usr.sbin/iscsid/vscsi.c
@@ -241,10 +241,13 @@ vscsi_callback(struct connection *c, void *arg, struct pdu *p)
 			status = VSCSI_STAT_SENSE;
 			/* stupid encoding of sense data in the data segment */
 			buf = pdu_getbuf(p, &n, PDU_DATA);
-			if (buf) {
-				size = buf[0] << 8 | buf[1];
-				buf += 2;
+			if (buf == NULL || n < 2) {
+				log_debug("vscsi_callback: bad scsi response");
+				conn_fail(c);
+				goto done;
 			}
+			size = buf[0] << 8 | buf[1];
+			buf += 2;
 			break;
 		default:
 			status = VSCSI_STAT_ERR;
@@ -279,6 +282,7 @@ send_status:
 		    t->target, t->lun);
 		log_pdu(p, 1);
 	}
+done:
 	pdu_free(p);
 }
```