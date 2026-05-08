# zero GPT partition size divides by zero

## Classification

denial of service, medium severity

## Affected Locations

`usr.sbin/installboot/efi_installboot.c:533`

## Summary

`findgptefisys()` accepts a checksum-valid GPT header with `gh_part_size == 0` and immediately divides the disk sector size by that value. A crafted GPT on an attacker-controlled target disk can therefore terminate a privileged `installboot` run with an integer divide-by-zero.

## Provenance

Reproduced and patched from a verified Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

A privileged operator runs `installboot` on a disk whose contents are attacker-controlled.

## Proof

`md_prepareboot()` and `md_installboot()` both call `findgptefisys()` on the target device before falling back to MBR FAT handling.

Inside `findgptefisys()`:

- The protective MBR is read and accepted by `gpt_chk_mbr()`.
- The GPT header is read from sector 1.
- The GPT signature, revision, header size, and header checksum are validated.
- `ghpartsize = letoh32(gh.gh_part_size)` is assigned from attacker-controlled GPT header bytes.
- `ghpartspersec = dl->d_secsize / ghpartsize` executes without checking whether `ghpartsize` is zero.

A disk image with a valid protective MBR and checksum-correct GPT header where `gh_part_size == 0` reaches the division before the partition-array checksum can reject the malformed GPT.

## Why This Is A Real Bug

The vulnerable value is read from attacker-controlled disk metadata after only GPT header-level validation. GPT header checksum validity does not imply semantic validity of `gh_part_size`. Because zero is accepted until the division, the process terminates while parsing untrusted disk contents.

The impact is an attacker-controlled input denial of service against a privileged operator's `installboot` invocation.

## Fix Requirement

Reject `gh_part_size == 0` before computing `dl->d_secsize / ghpartsize`.

## Patch Rationale

The patch adds a minimal semantic validation immediately after decoding `gh_part_size`. Returning `-1` preserves the existing invalid-GPT handling path and allows callers to continue normal fallback behavior instead of crashing.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/installboot/efi_installboot.c b/usr.sbin/installboot/efi_installboot.c
index 2118898..92263b2 100644
--- a/usr.sbin/installboot/efi_installboot.c
+++ b/usr.sbin/installboot/efi_installboot.c
@@ -534,6 +534,8 @@ findgptefisys(int devfd, struct disklabel *dl, int *gpartp,
 
 	off = letoh64(gh.gh_part_lba) * dl->d_secsize;
 	ghpartsize = letoh32(gh.gh_part_size);
+	if (ghpartsize == 0)
+		return (-1);
 	ghpartspersec = dl->d_secsize / ghpartsize;
 	ghpartnum = letoh32(gh.gh_part_num);
 	if ((secbuf = malloc(dl->d_secsize)) == NULL)
```