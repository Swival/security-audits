# avail ring descriptor index is not bounds checked

## Classification

High severity out-of-bounds read / memory-safety violation.

## Affected Locations

`usr.sbin/vmd/vioblk.c:278`

## Summary

`vioblk_notifyq()` accepts a descriptor index from the guest-controlled virtqueue avail ring and uses it to index the descriptor table before validating that the index is within the queue size. A malicious guest can place an out-of-range descriptor index in the avail ring and trigger host-side out-of-bounds descriptor reads in the vioblk process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Guest controls virtqueue memory.
- Guest notifies the vioblk virtqueue.
- The vioblk queue is configured with a finite queue size such as `vq_info->qs = 128`.

## Proof

The notify path is:

`handle_sync_io()` processes a guest notify write through `vioblk_write()`, which calls `vioblk_notifyq()` for `VIO1_NOTIFY_BAR_OFFSET`.

Inside `vioblk_notifyq()`:

```c
cmd_desc_idx = avail->ring[idx & vq_info->mask];
desc = &table[cmd_desc_idx];
cmd_len = desc->len;
```

`avail->ring[]` is guest-owned memory. The value loaded into `cmd_desc_idx` is not checked against `vq_info->qs` before `desc = &table[cmd_desc_idx]`.

Only later descriptor-chain indices are masked:

```c
desc = &table[desc->next & vq_info->mask];
```

A malicious guest can configure a normal vioblk queue with `qs = 128`, set `avail->idx = last_avail + 1`, place `128` or `65535` in the selected avail-ring slot, and notify queue 0. This causes the vioblk process to read `desc->len` and `desc->flags` outside the descriptor table before any reset/error path is reached.

## Why This Is A Real Bug

Virtio descriptor table entries are bounded by the negotiated queue size, `vq_info->qs`. The avail ring contains descriptor-head indices supplied by the guest, and those indices must identify valid descriptor-table entries.

Masking the avail-ring slot index only bounds access to `avail->ring[]`; it does not validate the descriptor index stored in that slot. As a result, an attacker-controlled value can address memory beyond the descriptor table. With the queue placed near the end of a mapped guest-memory range, a large descriptor index such as `65535` can drive the dereference outside the mapped virtqueue/guest range and fault the vioblk subprocess.

## Fix Requirement

Reject any avail-ring descriptor index where:

```c
cmd_desc_idx >= vq_info->qs
```

before indexing the descriptor table.

## Patch Rationale

The patch adds the missing bounds check immediately after reading the guest-controlled descriptor-head index and before computing `&table[cmd_desc_idx]`.

Invalid descriptor indices now follow the existing device reset path:

```c
dev->status |= DEVICE_NEEDS_RESET;
dev->isr |= VIRTIO_CONFIG_ISR_CONFIG_CHANGE;
```

This preserves the existing error-handling model while preventing the out-of-bounds descriptor-table read.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/vioblk.c b/usr.sbin/vmd/vioblk.c
index e8c193c..f0b2c20 100644
--- a/usr.sbin/vmd/vioblk.c
+++ b/usr.sbin/vmd/vioblk.c
@@ -284,6 +284,10 @@ vioblk_notifyq(struct virtio_dev *dev, uint16_t vq_idx)
 	while (idx != avail->idx) {
 		/* Retrieve Command descriptor. */
 		cmd_desc_idx = avail->ring[idx & vq_info->mask];
+		if (cmd_desc_idx >= vq_info->qs) {
+			log_warnx("%s: invalid cmd descriptor index", __func__);
+			goto reset;
+		}
 		desc = &table[cmd_desc_idx];
 		cmd_len = desc->len;
```