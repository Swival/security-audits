# Unchecked Virtqueue Ring Offsets Escape Mapped Vring

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.sbin/vmd/virtio.c:291`

## Summary

A malicious guest can program Virtio 1.x entropy queue `queue_avail` or `queue_used` addresses outside the mapped descriptor vring. `virtio_update_qa()` stores these guest-controlled values as unchecked offsets from `queue_desc`, while the host only maps `vring_size(qs)` bytes from `queue_desc`. On notification, `viornd_notifyq()` uses the unchecked offsets for host pointer arithmetic, then reads from `avail` and writes to `used`, causing out-of-vring host memory access.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and reproducer evidence.

## Preconditions

- Guest negotiates `VIRTIO_F_VERSION_1`.
- Guest configures and enables the in-process virtio entropy queue.
- Guest sets a valid `queue_desc` and queue size.
- Guest sets `queue_avail` or `queue_used` outside the `queue_desc` vring range.
- Guest notifies the entropy queue.

## Proof

`virtio_update_qa()` accepts guest-controlled Virtio 1.x queue configuration writes and maps only the descriptor-base vring:

- `vq_info->q_gpa = dev->pci_cfg.queue_desc`
- `vq_info->vq_availoffset = dev->pci_cfg.queue_avail - dev->pci_cfg.queue_desc`
- `vq_info->vq_usedoffset = dev->pci_cfg.queue_used - dev->pci_cfg.queue_desc`
- `hvaddr_mem(vq_info->q_gpa, vring_size(vq_info->qs))`

Before the patch, no check ensured that `queue_avail` or `queue_used` was greater than or equal to `queue_desc`, or that the corresponding ring extent fit within `vring_size(qs)`.

On notify, `viornd_notifyq()` derives host pointers from the unchecked offsets:

- `avail = (struct vring_avail *)(vr + vq_info->vq_availoffset)`
- `used = (struct vring_used *)(vr + vq_info->vq_usedoffset)`

It then reads through `avail`:

- `aidx = avail->idx & vq_info->mask`
- `dxx = avail->ring[aidx] & vq_info->mask`

And writes through `used`:

- `used->ring[uidx].id = dxx`
- `used->ring[uidx].len = sz`
- `used->idx++`

A practical trigger is to configure queue 0 with a valid descriptor base, place `queue_avail` or `queue_used` outside the mapped vring, enable the queue, and notify it. If the computed host address is unmapped, the VM process crashes. If it lands in mapped process memory, the entropy device performs out-of-vring reads or writes.

## Why This Is A Real Bug

The entropy device is handled in-process by the VM process. Guest PCI configuration writes directly control `queue_avail` and `queue_used`; those values are converted into offsets and later used as host virtual address offsets from `q_hva`.

The mapping covers only `vring_size(qs)` bytes starting at `queue_desc`, but the vulnerable code allowed the guest to choose ring offsets outside that mapped region. The subsequent `avail` reads and `used` writes are therefore not constrained to the mapped virtqueue. This is a guest-triggered memory-safety violation with denial-of-service impact and potential out-of-bounds host memory corruption when the derived address lands in mapped memory.

## Fix Requirement

Validate Virtio 1.x `queue_avail` and `queue_used` before enabling or storing the queue offsets:

- Both addresses must be greater than or equal to `queue_desc`.
- The full available ring extent must fit inside `vring_size(qs)`.
- The full used ring extent must fit inside `vring_size(qs)`.
- Invalid layouts must leave the queue disabled with zero offsets.

## Patch Rationale

The patch extends the existing Virtio 1.x queue-validity condition in `virtio_update_qa()`.

It now accepts the queue only when:

- `qs` is non-zero and even.
- `queue_avail >= queue_desc`.
- `queue_used >= queue_desc`.
- `queue_avail - queue_desc` leaves enough room for `sizeof(uint16_t) * (2 + qs)`.
- `queue_used - queue_desc` leaves enough room for `sizeof(uint16_t) * 2 + sizeof(struct vring_used_elem) * qs`.

This ensures that later `viornd_notifyq()` pointer derivations for `avail` and `used` remain within the `hvaddr_mem(queue_desc, vring_size(qs))` mapping for the ring structures they access. Invalid guest-supplied offsets fall through to the existing safe path that clears offsets and disables the queue.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/virtio.c b/usr.sbin/vmd/virtio.c
index 54c1c1d..dbcf9cb 100644
--- a/usr.sbin/vmd/virtio.c
+++ b/usr.sbin/vmd/virtio.c
@@ -212,7 +212,15 @@ virtio_update_qa(struct virtio_dev *dev)
 		vq_info->qs = dev->pci_cfg.queue_size;
 		vq_info->mask = vq_info->qs - 1;
 
-		if (vq_info->qs > 0 && vq_info->qs % 2 == 0) {
+		if (vq_info->qs > 0 && vq_info->qs % 2 == 0 &&
+		    dev->pci_cfg.queue_avail >= dev->pci_cfg.queue_desc &&
+		    dev->pci_cfg.queue_used >= dev->pci_cfg.queue_desc &&
+		    dev->pci_cfg.queue_avail - dev->pci_cfg.queue_desc <=
+		    vring_size(vq_info->qs) - sizeof(uint16_t) *
+		    (2 + vq_info->qs) &&
+		    dev->pci_cfg.queue_used - dev->pci_cfg.queue_desc <=
+		    vring_size(vq_info->qs) - (sizeof(uint16_t) * 2 +
+		    sizeof(struct vring_used_elem) * vq_info->qs)) {
 			vq_info->vq_availoffset = dev->pci_cfg.queue_avail -
 			    dev->pci_cfg.queue_desc;
 			vq_info->vq_usedoffset = dev->pci_cfg.queue_used -
```