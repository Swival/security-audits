# Invalid Virtqueue GPA Aborts VM Process

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/vmd/virtio.c:248`

## Summary

A malicious guest Virtio 1.x driver can write an invalid guest physical address to the PCI common configuration queue descriptor registers. `virtio_update_qa()` attempts to translate that guest-controlled GPA and calls `fatalx()` if translation fails, terminating the VM process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Guest can access Virtio 1.x PCI common configuration registers.

## Proof

- The guest negotiates `VIRTIO_F_VERSION_1`.
- The guest writes a 4-byte value such as `0xffffffff` to `VIO1_PCI_QUEUE_DESC + 4`.
- The BAR write reaches `virtio_io_dispatch()` through PCI I/O handling and is dispatched to `virtio_io_cfg()`.
- `virtio_io_cfg()` updates `pci_cfg->queue_desc` and immediately calls `virtio_update_qa()` at `usr.sbin/vmd/virtio.c:493`.
- In the Virtio 1.x branch, `virtio_update_qa()` copies the guest-controlled descriptor GPA into `vq_info->q_gpa` at `usr.sbin/vmd/virtio.c:208`.
- `virtio_update_qa()` calls `hvaddr_mem(vq_info->q_gpa, vring_size(vq_info->qs))` at `usr.sbin/vmd/virtio.c:246`.
- For GPAs outside VM memory, `hvaddr_mem()` returns `NULL` at `usr.sbin/vmd/x86_vm.c:861`.
- The original code then calls `fatalx()` at `usr.sbin/vmd/virtio.c:248`; `fatalx()` exits the process via `exit(1)` at `usr.sbin/vmd/log.c:193`.

## Why This Is A Real Bug

The invalid GPA is supplied entirely by the guest through documented Virtio 1.x PCI common configuration registers. Translation failure is therefore an expected validation failure for untrusted input, not an internal invariant violation. Calling `fatalx()` on this path lets a guest terminate its VM process and deny service.

## Fix Requirement

Reject invalid virtqueue GPA writes without terminating the VM process. The queue must not remain usable with an invalid mapping, and the device should signal an error state requiring reset.

## Patch Rationale

The patch replaces the fatal translation failure with non-fatal error handling:

- Logs the failed GPA-to-HVA translation with `log_warnx()`.
- Disables the affected virtqueue by setting `vq_info->vq_enabled = 0`.
- Clears the host virtual address mapping with `vq_info->q_hva = NULL`.
- Marks the device as needing reset with `dev->status |= DEVICE_NEEDS_RESET`.
- Returns without using an invalid mapping.

This preserves process availability while preventing later queue processing from dereferencing a missing or invalid vring mapping.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/virtio.c b/usr.sbin/vmd/virtio.c
index 54c1c1d..1ce49f0 100644
--- a/usr.sbin/vmd/virtio.c
+++ b/usr.sbin/vmd/virtio.c
@@ -244,8 +244,13 @@ virtio_update_qa(struct virtio_dev *dev)
 	/* Update any host va mappings. */
 	if (vq_info->q_gpa > 0) {
 		hva = hvaddr_mem(vq_info->q_gpa, vring_size(vq_info->qs));
-		if (hva == NULL)
-			fatalx("%s: failed to translate gpa to hva", __func__);
+		if (hva == NULL) {
+			log_warnx("%s: failed to translate gpa to hva", __func__);
+			vq_info->vq_enabled = 0;
+			vq_info->q_hva = NULL;
+			dev->status |= DEVICE_NEEDS_RESET;
+			return;
+		}
 		vq_info->q_hva = hva;
 	} else {
 		vq_info->q_hva = NULL;
```