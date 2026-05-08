# notify queue bounds check allows invalid configured-queue access

## Classification

High severity denial of service caused by an off-by-one queue bounds check in guest-controlled virtio block notification handling.

## Affected Locations

`usr.sbin/vmd/vioblk.c:263`

## Summary

A malicious guest can write the vioblk notify register with a queue index equal to `dev->num_queues`. `vioblk_notifyq()` rejects only indexes greater than `dev->num_queues`, so the equal case is accepted even though valid configured queue indexes are `0..dev->num_queues - 1`.

The accepted invalid index reaches `dev->vq[vq_idx]`, reads an unconfigured queue entry, observes `q_hva == NULL`, and calls `fatalx()`. This exits the host vioblk subprocess and causes the VM device path to fail, yielding guest-triggered denial of service.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Guest can write the vioblk notify register.
- The guest supplies a notify queue index equal to `dev->num_queues`.

## Proof

`vioblk_write()` handles `VIO1_NOTIFY_BAR_OFFSET` by calling:

```c
intr = vioblk_notifyq(dev, (uint16_t)(msg->data));
```

`vioblk_notifyq()` previously checked:

```c
if (vq_idx > dev->num_queues)
	return (0);
```

This permits `vq_idx == dev->num_queues`.

With one configured queue, notify value `1` is accepted. Only configured queues are initialized after the device-wide zeroing, so `dev->vq[1].q_hva` remains `NULL`. The function then executes:

```c
vq_info = &dev->vq[vq_idx];
idx = vq_info->last_avail;
vr = vq_info->q_hva;
if (vr == NULL)
	fatalx("%s: null vring", __func__);
```

`fatalx()` exits the vioblk host subprocess. The VM parent treats the device pipe EOF or event-loop exit as fatal, causing a guest-triggered VM/device denial of service.

## Why This Is A Real Bug

Valid configured queue indexes are strictly less than `dev->num_queues`. Accepting `vq_idx == dev->num_queues` violates that invariant.

Although the physical `dev->vq` array has `VIRTIO_MAX_QUEUES` slots, the accepted index is outside the configured queue range. The invalid configured-queue access deterministically reaches an uninitialized queue entry and terminates the host vioblk subprocess through `fatalx()`.

## Fix Requirement

Reject notify queue indexes where:

```c
vq_idx >= dev->num_queues
```

before indexing `dev->vq`.

## Patch Rationale

Changing the comparison from `>` to `>=` enforces the configured queue bound exactly. It preserves valid queue index `0..dev->num_queues - 1` and rejects the first invalid index, including the reproduced guest-controlled value equal to `dev->num_queues`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vioblk.c b/usr.sbin/vmd/vioblk.c
index e8c193c..c039aff 100644
--- a/usr.sbin/vmd/vioblk.c
+++ b/usr.sbin/vmd/vioblk.c
@@ -267,7 +267,7 @@ vioblk_notifyq(struct virtio_dev *dev, uint16_t vq_idx)
 	struct vioblk_dev *vioblk = &dev->vioblk;
 
 	/* Invalid queue? */
-	if (vq_idx > dev->num_queues)
+	if (vq_idx >= dev->num_queues)
 		return (0);
 
 	vq_info = &dev->vq[vq_idx];
```