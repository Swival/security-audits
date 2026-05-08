# device-controlled block descriptor length indexes past stack buffer

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.bin/cdio/mmc.c:398`

## Summary

`writetao()` trusts the MODE SENSE block descriptor length byte returned by the selected SCSI device. A malicious device can set `modebuf[7]` large enough that subsequent writes index past the fixed 70-byte stack buffer `modebuf`, corrupting stack memory during a user-initiated `cdio tao` write operation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- User runs a `cdio` TAO write operation.
- The selected cdrom/SCSI device is attacker-controlled or malicious.
- The device returns a crafted MODE SENSE response with `modebuf[7] >= 60`.

## Proof

Reachability is confirmed:

- `cdio tao ...` dispatches to `tao()` at `usr.bin/cdio/cdio.c:282`.
- `tao()` opens the selected device for writing at `usr.bin/cdio/cdio.c:662`.
- `tao()` calls `writetao()` at `usr.bin/cdio/cdio.c:678`.

Device control is confirmed:

- `writetao()` allocates `u_char modebuf[70]` at `usr.bin/cdio/mmc.c:389`.
- `writetao()` passes `modebuf` to `mode_sense_write()` at `usr.bin/cdio/mmc.c:393`.
- `mode_sense_write()` performs a SCSI MODE SENSE read of `0x46` bytes into that caller-provided buffer at `usr.bin/cdio/mmc.c:538` and `usr.bin/cdio/mmc.c:540`.

The failing operation is direct:

```c
bdlen = modebuf[7];
modebuf[2+8+bdlen] |= 0x40;
```

If the malicious device returns `modebuf[7] == 60`, then the first write targets:

```text
2 + 8 + 60 = 70
```

`modebuf` has valid indexes `0..69`, so index `70` is one byte past the stack buffer. Larger `bdlen` values write farther out of bounds. The later writes to `modebuf[3+8+bdlen]`, `modebuf[4+8+bdlen]`, and `modebuf[8+8+bdlen]` are also unsafe without validation.

## Why This Is A Real Bug

The block descriptor length is read from device-controlled MODE SENSE data and is used as an unchecked offset into a fixed-size stack buffer. The code performs writes through that computed offset before any track data is written. With `bdlen >= 60`, the computed index exceeds the 70-byte buffer boundary, causing stack memory corruption.

## Fix Requirement

Validate `bdlen` before modifying `modebuf`. The validation must ensure every index written by `writetao()` is within `sizeof(modebuf)`, including the largest required offset, `8 + 8 + bdlen`.

## Patch Rationale

The patch rejects MODE SENSE data whose block descriptor length would make the largest later write index outside `modebuf`.

The largest accessed index is:

```c
modebuf[8+8+bdlen]
```

Therefore this guard is sufficient for all subsequent writes:

```c
if (8 + 8 + bdlen >= sizeof(modebuf)) {
	warnx("invalid block descriptor length");
	return (-1);
}
```

For a 70-byte buffer, this rejects `bdlen >= 54`, because `16 + bdlen` must be at most `69`. The known trigger value `bdlen == 60` is rejected before any out-of-bounds write occurs.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/cdio/mmc.c b/usr.bin/cdio/mmc.c
index 06b47ab..c51d83e 100644
--- a/usr.bin/cdio/mmc.c
+++ b/usr.bin/cdio/mmc.c
@@ -395,6 +395,10 @@ writetao(struct track_head *thp)
 		return (r);
 	}
 	bdlen = modebuf[7];
+	if (8 + 8 + bdlen >= sizeof(modebuf)) {
+		warnx("invalid block descriptor length");
+		return (-1);
+	}
 	modebuf[2+8+bdlen] |= 0x40; /* Buffer Underrun Free Enable */
 	modebuf[2+8+bdlen] |= 0x01; /* change write type to TAO */
```