# SMART selftest log index reads past stack buffer

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`sbin/atactl/atactl.c:1532`

## Summary

`atactl smartreadlog selftest` trusts the SMART self-test log `index` byte returned by the device. The log contains only 21 self-test descriptors, but the code accepts any nonzero `index`, subtracts one, and immediately indexes `data->desc[i]`. A malicious ATA device can return a checksum-valid SMART self-test log with `index > 21`, causing reads past the stack-resident 512-byte sector buffer while formatting output.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was manually reproduced and patched.

## Preconditions

- User runs `atactl <dev> smartreadlog selftest`.
- The target ATA device is attacker-controlled or returns attacker-controlled SMART log data.
- The device returns a checksum-valid SMART self-test log.
- The SMART self-test log has `index > 21`.

## Proof

`device_smart_readlog` reads one 512-byte sector into stack buffer `inbuf`, casts it to `struct smart_log_self *`, and validates only the checksum.

For the `selftest` case:

- `struct smart_log_self` contains `desc[21]`.
- `index` is a device-controlled `u_int8_t` at offset 508.
- The vulnerable code checks only `data->index == 0`.
- It then computes `i = data->index - 1`.
- With `index = 22`, `i == 21`, which is one past `desc[20]`.
- The empty-entry check reads `data->desc[21].time1` and `data->desc[21].time2`.
- The later failing-LBA print evaluates `data->desc[21].lbafail2` through `data->desc[21].lbafail4`, reaching offsets 512 through 514, past the 512-byte stack buffer.

This produces an out-of-bounds stack read driven by device-supplied SMART log contents.

## Why This Is A Real Bug

The SMART self-test log uses a 21-entry circular buffer. Valid indices are `1..21`; `0` means no entries. The code handles `0` but does not reject values above 21 before using the index.

Because the log sector is supplied by the device, checksum validity does not constrain `index` to the descriptor array bounds. A malicious device can choose both `index` and checksum bytes, making the invalid index reachable through normal command execution.

## Fix Requirement

Reject or clamp `data->index` to the valid self-test descriptor range before indexing `data->desc`.

The safe range is:

```c
1 <= data->index && data->index <= 21
```

## Patch Rationale

The patch rejects malformed self-test logs with `index > 21` immediately after the existing `index == 0` no-entry handling and before `i = data->index - 1`.

This preserves existing behavior for valid logs, keeps `0` as the no-entry sentinel, and prevents all subsequent descriptor reads from using an out-of-range circular-buffer index.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/atactl/atactl.c b/sbin/atactl/atactl.c
index 2a47fc3..f2dc75b 100644
--- a/sbin/atactl/atactl.c
+++ b/sbin/atactl/atactl.c
@@ -1527,6 +1527,8 @@ device_smart_readlog(int argc, char *argv[])
 			printf("No log entries\n");
 			return;
 		}
+		if (data->index > 21)
+			errx(1, "Invalid self-test log index");
 
 		/* circular buffer of 21 entries */
 		i = data->index - 1;
```