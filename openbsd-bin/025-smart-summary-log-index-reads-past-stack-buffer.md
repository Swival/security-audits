# SMART summary log index reads past stack buffer

## Classification

Out-of-bounds read; medium severity.

## Affected Locations

`sbin/atactl/atactl.c:919`

## Summary

`atactl smartreadlog summary` trusts the SMART summary log `index` field after only validating the sector checksum. The summary log contains five `errdata` entries, but the code uses `data->index - 1` directly as an array index. A malicious ATA device can return a checksum-valid sector with `index > 5`, causing `smart_print_errdata()` to read outside the five-entry array and potentially beyond the 512-byte stack buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A privileged user runs:

```sh
atactl <device> smartreadlog summary
```

against a malicious or compromised ATA device that returns attacker-controlled SMART summary log data.

## Proof

The SMART READ LOG path reads one `DEV_BSIZE` sector into stack buffer `inbuf`, casts it to `struct smart_log_sum`, and validates only `smart_cksum(inbuf, sizeof(inbuf))`.

In the `summary` branch:

```c
i = data->index - 1;
smart_print_errdata(&data->errdata[i--]);
```

`struct smart_log_sum` has exactly five `errdata` entries. With a checksum-valid sector containing `index = 6` and `err_cnt = 1`, `i` becomes `5`, so `data->errdata[5]` is passed to `smart_print_errdata()`.

The reproduced harness mirrored the committed structs and control flow. ASan reported a stack-buffer-overflow read when `smart_print_errdata(&data->errdata[5])` executed. The same arithmetic shows that `errdata[5]` starts outside the five-entry array and overlaps trailing structure fields; subsequent field reads can extend past the 512-byte stack sector.

## Why This Is A Real Bug

The device controls `data->index`, and a valid SMART checksum does not constrain the semantic range of that field. The code already treats `index == 0` specially but does not reject values above the five-entry circular buffer size. Therefore `index = 6` is accepted and deterministically produces an out-of-bounds read during normal output formatting.

The impact is denial of service via process crash and possible stack-byte disclosure through printed SMART error fields.

## Fix Requirement

Reject or otherwise constrain `data->index` to the valid SMART summary circular-buffer range `1..5` before indexing `data->errdata`.

## Patch Rationale

The patch rejects `data->index > 5` immediately after the existing `index == 0` no-entry handling and before computing `i = data->index - 1`.

This preserves valid behavior for entries `1..5`, keeps the existing no-entry behavior for `0`, and prevents all out-of-range positive indexes from reaching `smart_print_errdata()`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/atactl/atactl.c b/sbin/atactl/atactl.c
index 2a47fc3..9a8dbf6 100644
--- a/sbin/atactl/atactl.c
+++ b/sbin/atactl/atactl.c
@@ -1448,6 +1448,8 @@ device_smart_readlog(int argc, char *argv[])
 			printf("No log entries\n");
 			return;
 		}
+		if (data->index > 5)
+			errx(1, "Invalid SMART log index");
 
 		nerr = letoh16(data->err_cnt);
 		printf("Error count: %d\n\n", nerr);
```