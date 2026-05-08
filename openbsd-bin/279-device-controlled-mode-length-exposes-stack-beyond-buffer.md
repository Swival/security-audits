# device-controlled mode length exposes stack beyond buffer

## Classification

Information disclosure, medium severity.

## Affected Locations

`usr.bin/cdio/mmc.c:567`

## Summary

`writetao()` stores MODE SENSE data in a 70-byte stack buffer and later sends that same buffer with MODE SELECT. The MODE SELECT transfer length is derived from device-controlled `buf[0]` and `buf[1]` without checking that the computed length fits the local buffer. A malicious SCSI device can report an oversized mode data length and cause adjacent stack bytes to be transmitted back to the device.

## Provenance

Verified from the provided source, reproduced trigger analysis, and patch.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- User runs a `cdio` write operation.
- The selected CD-ROM/SCSI device is malicious or attacker-controlled.
- The malicious device returns a successful MODE SENSE response with an oversized mode data length.

## Proof

`writetao()` allocates a fixed stack buffer:

```c
u_char modebuf[70], bdlen;
```

It passes that buffer to `mode_sense_write(modebuf)`, which performs a MODE SENSE read into the caller-provided buffer with a requested length of `0x46` bytes.

The malicious device controls the mode data length bytes stored in `modebuf[0]` and `modebuf[1]`. `mode_sense_write()` returns only the SCSI status and does not validate those length bytes.

A concrete reproducing response is:

```text
modebuf[0] = 0x00
modebuf[1] = 0x80
modebuf[7] = 0x00
```

With `modebuf[7] = 0`, the later `writetao()` modifications remain within the 70-byte buffer. Then `mode_select_write(modebuf)` computes:

```c
scb->length[1] = 2 + buf[1] + 256 * buf[0];
scr.datalen = 2 + buf[1] + 256 * buf[0];
scr.databuf = (caddr_t)buf;
```

For the example above, `scr.datalen` becomes `130`, while `scr.databuf` still points to the 70-byte stack object. The `SCIOCCOMMAND` MODE SELECT write therefore reads past `modebuf` and sends adjacent stack contents to the malicious device.

## Why This Is A Real Bug

The transfer length used for a data-out SCSI command is trusted from device-supplied MODE SENSE bytes. The local object passed as `scr.databuf` is only 70 bytes, but `scr.datalen` can exceed 70. Because `SCCMD_WRITE` causes host memory to be sent to the device, the out-of-bounds read is externally observable by the malicious device as leaked stack data.

The reproduced low-byte trigger is sufficient: `buf[0] = 0` and `buf[1] = 0x80` request 130 bytes from a 70-byte stack buffer.

## Fix Requirement

Reject MODE SELECT lengths that exceed the local 70-byte MODE SENSE buffer before assigning the command transfer length.

For a 70-byte buffer, the encoded mode data length must satisfy:

```text
2 + buf[1] + 256 * buf[0] <= 70
```

Therefore valid values for this buffer require:

```text
buf[0] == 0
buf[1] <= 0x44
```

## Patch Rationale

The patch adds a bounds check before `scb->length[1]` and `scr.datalen` are derived from `buf[0]` and `buf[1]`:

```c
if (buf[0] != 0 || buf[1] > 0x44)
	return (-1);
```

This rejects any length that would make `2 + buf[1] + 256 * buf[0]` exceed 70 bytes. It also rejects nonzero high-byte lengths, preventing both oversized transfers and truncation effects from assigning only `scb->length[1]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/cdio/mmc.c b/usr.bin/cdio/mmc.c
index 06b47ab..2fcf191 100644
--- a/usr.bin/cdio/mmc.c
+++ b/usr.bin/cdio/mmc.c
@@ -560,6 +560,8 @@ mode_select_write(unsigned char buf[])
 	 * describe it.
 	 */
 	scb->byte2 = 0x10;
+	if (buf[0] != 0 || buf[1] > 0x44)
+		return (-1);
 	scb->length[1] = 2 + buf[1] + 256 * buf[0];
 	scr.timeout = 4000;
 	scr.senselen = SENSEBUFLEN;
```