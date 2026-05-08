# guest notify index escapes virtqueue array

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`usr.sbin/vmd/vioscsi.c:577`

`usr.sbin/vmd/vioscsi.c:2192`

## Summary

A malicious VM guest can write an unchecked virtqueue index to the vioscsi virtio notify BAR. The vioscsi device process forwards that value to `vioscsi_notifyq`, which indexes `dev->vq[vq_idx]` before validating that `vq_idx` is within the configured queue count. An out-of-range notify value can therefore cause host-side out-of-bounds memory access in the vioscsi device process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- Guest has access to the vioscsi virtio notify BAR.
- Guest can issue a notify BAR write with a chosen virtqueue index.
- The supplied index is greater than or equal to the configured vioscsi queue count.

## Proof

The reproduced path is:

- `usr.sbin/vmd/vioscsi.c:546` handles a synchronous device I/O message and calls `vioscsi_write`.
- `usr.sbin/vmd/vioscsi.c:577` handles `VIO1_NOTIFY_BAR_OFFSET` by calling `vioscsi_notifyq(dev, (uint16_t)(msg->data))`.
- The notify value is guest-controlled and is not checked before the call.
- `usr.sbin/vmd/vioscsi.c:2192` immediately computes `vq_info = &dev->vq[vq_idx]`.
- Subsequent code reads fields through that out-of-bounds `vq_info`, including `q_hva`, `vq_availoffset`, `vq_usedoffset`, `last_avail`, `mask`, and `qs`.

The checked helper path does not mitigate this case: `usr.sbin/vmd/virtio.c:670` limits `virtio_io_notify` to in-process devices and rejects SCSI, while vioscsi uses the multiprocess `virtio_pci_io`/imsg path.

A guest-supplied `vq_idx >= 3` escapes the vioscsi virtqueue array before validation.

## Why This Is A Real Bug

`vq_idx` originates from guest-controlled notify BAR data. The code uses that value as an array index into `dev->vq` without checking it against the configured number of queues. This is a direct out-of-bounds read in the host vioscsi device process.

The security impact is guest-triggered denial of service of the host device process, with later dereferences based on fields read from memory outside the intended virtqueue array.

## Fix Requirement

Reject notify indices where `vq_idx >= dev->num_queues` before computing `&dev->vq[vq_idx]` or reading any queue fields.

## Patch Rationale

The patch adds the bounds check at the start of `vioscsi_notifyq`, before the first access to `dev->vq[vq_idx]`.

For invalid indices, the function logs the rejected virtqueue index and returns `0`, meaning no interrupt is generated and no queue processing occurs. This preserves existing behavior for valid queue indices while preventing out-of-bounds access for malicious notify values.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vioscsi.c b/usr.sbin/vmd/vioscsi.c
index 6f3aa17..24bd3fd 100644
--- a/usr.sbin/vmd/vioscsi.c
+++ b/usr.sbin/vmd/vioscsi.c
@@ -2189,6 +2189,10 @@ vioscsi_notifyq(struct virtio_dev *dev, uint16_t vq_idx)
 	struct virtio_vq_acct acct;
 	struct virtio_vq_info *vq_info;
 
+	if (vq_idx >= dev->num_queues) {
+		log_warnx("%s: invalid virtqueue index %u", __func__, vq_idx);
+		return (0);
+	}
 	vq_info = &dev->vq[vq_idx];
 	vr = vq_info->q_hva;
 	if (vr == NULL)
```