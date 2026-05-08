# Excessive GPT Partition Count Overflows Stack Array

## Classification

Out-of-bounds write; medium severity; confidence certain.

## Affected Locations

`usr.sbin/installboot/i386_installboot.c:581`

## Summary

`findgptefisys()` allocates a fixed stack array for `NGPTPARTITIONS` GPT entries but trusts the on-disk GPT header’s `gh_part_num`. A valid-checksum GPT header advertising more than `NGPTPARTITIONS` entries causes the partition-copy loop to write past the end of the stack array before the partition-table checksum is validated.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A privileged user runs `installboot` on an attacker-controlled disk image or device.

## Proof

`findgptefisys()` declares:

```c
struct gpt_partition gp[NGPTPARTITIONS];
```

`NGPTPARTITIONS` is 128.

The function validates the protective MBR, GPT signature, revision, header size, and GPT header checksum, then reads:

```c
ghpartnum = letoh32(gh.gh_part_num);
```

Before the patch, no bound checked `ghpartnum` against `NGPTPARTITIONS`.

With 512-byte sectors and `gh_part_size = 128`, `ghpartspersec` is 4. A GPT header with a valid header checksum and `gh_part_num = 129` makes the loop run 33 iterations:

```c
for (i = 0; i < (ghpartnum + ghpartspersec - 1) / ghpartspersec; i++) {
	memcpy(gp + i * ghpartspersec, secbuf,
	    ghpartspersec * sizeof(struct gpt_partition));
}
```

On the final iteration, `i == 32`, so the destination is `gp + 128`, immediately past the fixed `gp[128]` stack array. The `memcpy()` writes one full sector of GPT entries past the stack object.

The partition-table checksum is computed only after the copy:

```c
new_csum = crc32((unsigned char *)&gp, ghpartnum * ghpartsize);
```

Therefore the checksum does not prevent the overflow.

## Why This Is A Real Bug

The attacker-controlled GPT header value directly controls the number of partition-entry sectors copied into a fixed-size stack array. The code reaches this copy path from `md_prepareboot()` and `md_installboot()` through `findgptefisys()` while parsing target disk contents. Because `installboot` is normally run with elevated privileges and operates on raw disk devices or images, malicious disk contents can cause privileged stack memory corruption.

## Fix Requirement

Reject GPT headers where `gh_part_num` exceeds `NGPTPARTITIONS` before allocating the sector buffer and before copying partition entries into `gp`.

## Patch Rationale

The patch adds a direct upper-bound check immediately after decoding `gh_part_num`:

```c
if (ghpartnum > NGPTPARTITIONS)
	return (-1);
```

This preserves the existing fixed-size stack array design while ensuring the later partition-copy loop cannot address beyond `gp[NGPTPARTITIONS - 1]` due to an excessive on-disk partition count.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/installboot/i386_installboot.c b/usr.sbin/installboot/i386_installboot.c
index d1830fb..4909bc3 100644
--- a/usr.sbin/installboot/i386_installboot.c
+++ b/usr.sbin/installboot/i386_installboot.c
@@ -667,6 +667,8 @@ findgptefisys(int devfd, struct disklabel *dl, int *gpartp,
 	ghpartsize = letoh32(gh.gh_part_size);
 	ghpartspersec = dl->d_secsize / ghpartsize;
 	ghpartnum = letoh32(gh.gh_part_num);
+	if (ghpartnum > NGPTPARTITIONS)
+		return (-1);
 	if ((secbuf = malloc(dl->d_secsize)) == NULL)
 		err(1, NULL);
 	for (i = 0; i < (ghpartnum + ghpartspersec - 1) / ghpartspersec; i++) {
```