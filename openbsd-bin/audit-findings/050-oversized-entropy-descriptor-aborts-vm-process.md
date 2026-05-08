# Oversized Entropy Descriptor Aborts VM Process

## Classification

denial of service, medium severity, certain confidence

## Affected Locations

`usr.sbin/vmd/virtio.c:298`

## Summary

A malicious guest virtio entropy driver can place an oversized descriptor in the entropy virtqueue and notify the device. `viornd_notifyq()` trusts the guest-controlled descriptor length enough to call `fatalx()` when it exceeds `MAXPHYS`, which exits the VM process and denies service to that guest VM.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The guest has the virtio entropy device enabled.
- The guest can configure and enable the entropy virtqueue.
- The guest controls descriptor contents in guest RAM.

## Proof

`virtio_io_notify()` dispatches guest notify writes for in-process virtio devices. For `PCI_PRODUCT_VIRTIO_ENTROPY`, it calls `viornd_notifyq(dev, vq_idx)`.

Inside `viornd_notifyq()`:

- `vq_info->q_hva` maps the guest-provided vring.
- `avail->idx` and `avail->ring[aidx]` select descriptor index `dxx`.
- `desc[dxx].len` is copied into `sz`.
- If `sz > MAXPHYS`, the original code calls `fatalx("viornd descriptor size too large (%zu)", sz)`.

The reproducer confirmed that `fatalx()` exits the current process via `exit(1)` in `usr.sbin/vmd/log.c:193`. For the in-process entropy device, this is the VM process. The parent `vmm` process then handles the VM child exit and removes the VM through `terminate_vm` in `usr.sbin/vmd/vmm.c:338`.

A malicious guest can set `desc[dxx].len = MAXPHYS + 1`, place `dxx` in the available ring slot selected by the code, and notify queue 0 after enabling the queue. No validation rejects this descriptor before the original `fatalx()` path.

## Why This Is A Real Bug

The descriptor length is guest-controlled input. Oversized or invalid guest input is expected in a virtual device model and must not terminate the VM process. The original code converts a recoverable guest-supplied malformed descriptor into an unconditional process abort, causing denial of service to the guest VM.

## Fix Requirement

Reject oversized entropy descriptors without aborting the VM process. The handler should log the malformed descriptor and return without allocating memory, writing random data, updating the used ring, or raising an interrupt.

## Patch Rationale

The patch replaces the `fatalx()` call with `log_warnx()` and `return (0)` when `sz > MAXPHYS`.

This preserves the existing size limit while changing the failure mode from process termination to safe rejection. Returning `0` matches the function’s existing convention for “no interrupt needed” and prevents downstream use of the oversized length in `malloc()`, `arc4random_buf()`, and `write_mem()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/virtio.c b/usr.sbin/vmd/virtio.c
index 54c1c1d..d3c27b1 100644
--- a/usr.sbin/vmd/virtio.c
+++ b/usr.sbin/vmd/virtio.c
@@ -294,8 +294,10 @@ viornd_notifyq(struct virtio_dev *dev, uint16_t idx)
 	dxx = avail->ring[aidx] & vq_info->mask;
 
 	sz = desc[dxx].len;
-	if (sz > MAXPHYS)
-		fatalx("viornd descriptor size too large (%zu)", sz);
+	if (sz > MAXPHYS) {
+		log_warnx("viornd descriptor size too large (%zu)", sz);
+		return (0);
+	}
 
 	rnd_data = malloc(sz);
 	if (rnd_data == NULL)
```