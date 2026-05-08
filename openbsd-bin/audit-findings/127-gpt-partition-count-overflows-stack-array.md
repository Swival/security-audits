# GPT partition count overflows stack array

## Classification

High severity out-of-bounds write / stack memory corruption.

## Affected Locations

`usr.sbin/installboot/efi_installboot.c:543`

## Summary

`findgptefisys()` stores GPT entries in a fixed stack array `gp[NGPTPARTITIONS]` but trusts the on-disk GPT header field `gh_part_num`. A crafted GPT with `gh_part_num > NGPTPARTITIONS` causes the GPT entry copy loop to write past the end of `gp`.

## Provenance

Reproduced and patched from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

Privileged `installboot` scans an attacker-controlled disk image or disk contents.

## Proof

`findgptefisys()` declares:

```c
struct gpt_partition gp[NGPTPARTITIONS];
```

It then reads attacker-controlled GPT metadata:

```c
ghpartnum = letoh32(gh.gh_part_num);
```

Before the patch, `ghpartnum` was not bounded against `NGPTPARTITIONS`. The loop copied full sectors of GPT entries into `gp`:

```c
memcpy(gp + i * ghpartspersec, secbuf,
    ghpartspersec * sizeof(struct gpt_partition));
```

With a normal 512-byte sector and 128-byte GPT entries, `ghpartspersec == 4`. If a crafted valid GPT header sets `gh_part_num == 129`, the loop reaches `i == 32` and copies 512 bytes starting at `gp[128]`, which is one element past the 128-entry stack array.

Existing validation does not prevent this: the protective MBR, GPT signature, revision, header size, and header CRC can be valid, while the partition-array checksum is checked only after the overflowing copies.

## Why This Is A Real Bug

The overwrite occurs before the partition-array checksum validation, so a malformed partition count can corrupt stack memory during parsing. A lower-privileged actor who controls disk or image contents processed by privileged `installboot` can trigger attacker-controlled corruption in the privileged process. This is a practical denial of service and may have stronger impact depending on platform mitigations and stack layout.

## Fix Requirement

Reject GPT headers whose `gh_part_num` exceeds the fixed local capacity `NGPTPARTITIONS` before allocating the sector buffer or copying partition entries.

## Patch Rationale

The patch adds a direct bounds check immediately after decoding `gh_part_num`:

```c
if (ghpartnum > NGPTPARTITIONS)
    return (-1);
```

This preserves existing behavior for supported GPT layouts and safely rejects oversized partition tables before the `memcpy()` loop can address beyond `gp`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/installboot/efi_installboot.c b/usr.sbin/installboot/efi_installboot.c
index 2118898..be6d5c9 100644
--- a/usr.sbin/installboot/efi_installboot.c
+++ b/usr.sbin/installboot/efi_installboot.c
@@ -536,6 +536,8 @@ findgptefisys(int devfd, struct disklabel *dl, int *gpartp,
 	ghpartsize = letoh32(gh.gh_part_size);
 	ghpartspersec = dl->d_secsize / ghpartsize;
 	ghpartnum = letoh32(gh.gh_part_num);
+	if (ghpartnum > NGPTPARTITIONS)
+		return (-1);
 	if ((secbuf = malloc(dl->d_secsize)) == NULL)
 		err(1, NULL);
 	for (i = 0; i < (ghpartnum + ghpartspersec - 1) / ghpartspersec; i++) {
```