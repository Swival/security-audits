# Zero-Length Response Descriptor Hangs READ_10 Processing

## Classification

- Type: denial of service
- Severity: medium
- Confidence: certain

## Affected Locations

- `usr.sbin/vmd/vioscsi.c:1359`
- `usr.sbin/vmd/vioscsi.c:237`
- `usr.sbin/vmd/vioscsi.c:1437`
- `usr.sbin/vmd/vioscsi.c:1496`
- `usr.sbin/vmd/vioscsi.c:1510`
- `usr.sbin/vmd/vioscsi.c:1512`
- `usr.sbin/vmd/vioscsi.c:1519`
- `usr.sbin/vmd/vioscsi.c:1522`

## Summary

A malicious VM guest can make `vioscsi_handle_read_10()` spin forever by supplying a zero-length response/data descriptor during a successful nonzero `READ_10`. The handler repeatedly follows the same guest-controlled descriptor, performs zero-byte writes, and never advances `chunk_offset`, preventing completion of the SCSI request and blocking the single-threaded vioscsi event loop.

## Provenance

- Verified from the provided reproduced finding and source analysis.
- Scanner provenance: [Swival Security Scanner](https://swival.dev)

## Preconditions

- Virtio SCSI is attached.
- A nonzero `READ_10` request succeeds from the backing media.
- The guest controls the vring descriptor chain.
- The response/data descriptor after the status response has `len = 0`.
- The zero-length descriptor can point back to itself via `next`.

## Proof

The reproduced path is:

1. A malicious guest submits a valid nonzero `READ_10` CDB/LBA.
2. `vioscsi_start_read()` sets a nonzero `info->len` at `usr.sbin/vmd/vioscsi.c:1437`.
3. `vioscsi_next_ring_desc()` blindly follows `cur->next & mask` at `usr.sbin/vmd/vioscsi.c:237`.
4. The `READ_10` chunk loop advances to the guest-controlled response/data descriptor at `usr.sbin/vmd/vioscsi.c:1496`.
5. With descriptor `len = 0`, `chunk_len` becomes `0` at `usr.sbin/vmd/vioscsi.c:1510`.
6. `write_mem()` is called with length `0` at `usr.sbin/vmd/vioscsi.c:1512`.
7. `chunk_offset += acct->resp_desc->len` adds `0` at `usr.sbin/vmd/vioscsi.c:1519`.
8. Because `info->len` is nonzero, `chunk_offset < info->len` remains true and the loop never reaches completion at `usr.sbin/vmd/vioscsi.c:1522`.

A self-referential zero-length descriptor therefore causes unbounded looping in `vioscsi_handle_read_10()`.

## Why This Is A Real Bug

The descriptor chain is guest-controlled, and the code does not validate that each chunk iteration makes forward progress. A zero-length descriptor is sufficient to keep `chunk_offset` unchanged while the loop condition remains true. Since vioscsi runs in a single-threaded event loop for the VM, this infinite loop stops SCSI request processing for that VM and constitutes a reliable denial of service.

## Fix Requirement

Reject zero-length data descriptors, or otherwise require forward progress before continuing the `READ_10` chunk loop.

## Patch Rationale

The patch checks for `chunk_len == 0` while unread data remains. In that case, it logs the malformed descriptor and exits through `free_read_10`, releasing the allocated read buffer and returning without entering an infinite loop. This directly enforces forward progress for every loop iteration that still has pending data.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vioscsi.c b/usr.sbin/vmd/vioscsi.c
index 6f3aa17..a2f5009 100644
--- a/usr.sbin/vmd/vioscsi.c
+++ b/usr.sbin/vmd/vioscsi.c
@@ -1509,6 +1509,11 @@ vioscsi_handle_read_10(struct virtio_dev *dev,
 		} else
 			chunk_len = acct->resp_desc->len;
 
+		if (chunk_len == 0 && chunk_offset < info->len) {
+			log_warnx("%s: zero-length read_buf descriptor", __func__);
+			goto free_read_10;
+		}
+
 		if (write_mem(acct->resp_desc->addr, read_buf + chunk_offset,
 			chunk_len)) {
 			log_warnx("%s: unable to write read_buf"
```