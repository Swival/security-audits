# zero GPT partition size divides by zero

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`usr.sbin/installboot/i386_installboot.c:667`

## Summary

`findgptefisys()` trusted the GPT header partition-entry size before using it as a divisor. A crafted GPT header with a valid attacker-computable checksum and `gh_part_size == 0` reached `dl->d_secsize / ghpartsize`, causing deterministic divide-by-zero termination during `installboot` disk parsing.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A privileged user runs `installboot` on an attacker-controlled disk or disk image.

## Proof

The GPT parsing path accepts a protective MBR when `gpt_chk_mbr()` returns 0. It then validates the GPT header signature, revision, header size, and header checksum, but did not validate `gh_part_size` before use.

The vulnerable sequence was:

```c
off = letoh64(gh.gh_part_lba) * dl->d_secsize;
ghpartsize = letoh32(gh.gh_part_size);
ghpartspersec = dl->d_secsize / ghpartsize;
```

Because the checksum is computed over attacker-controlled header bytes with `gh_csum` zeroed, an attacker can construct a valid-checksum GPT header whose `gh_part_size` is zero. That input deterministically reaches the unsigned division by zero before `findgptefisys()` returns.

## Why This Is A Real Bug

The value is read directly from disk metadata controlled by the target device. Existing checks do not constrain `gh_part_size`, and the first operation using it is division. A zero partition-entry size is invalid GPT metadata and crashes the privileged utility instead of being rejected as malformed input.

## Fix Requirement

Reject zero and otherwise nonsensical GPT partition-entry sizes before any division or copy-size calculation. The accepted size must match the parser’s fixed `struct gpt_partition` layout.

## Patch Rationale

The patch validates `ghpartsize` immediately after decoding it and before it is used as a divisor:

```c
ghpartsize = letoh32(gh.gh_part_size);
if (ghpartsize != sizeof(struct gpt_partition))
	return (-1);
ghpartspersec = dl->d_secsize / ghpartsize;
```

Requiring `gh_part_size == sizeof(struct gpt_partition)` eliminates the divide-by-zero case and prevents mismatched GPT entry sizes from driving later reads, copies, and checksum calculations that assume the local fixed structure size.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/installboot/i386_installboot.c b/usr.sbin/installboot/i386_installboot.c
index d1830fb..7caaa4b 100644
--- a/usr.sbin/installboot/i386_installboot.c
+++ b/usr.sbin/installboot/i386_installboot.c
@@ -665,6 +665,8 @@ findgptefisys(int devfd, struct disklabel *dl, int *gpartp,
 
 	off = letoh64(gh.gh_part_lba) * dl->d_secsize;
 	ghpartsize = letoh32(gh.gh_part_size);
+	if (ghpartsize != sizeof(struct gpt_partition))
+		return (-1);
 	ghpartspersec = dl->d_secsize / ghpartsize;
 	ghpartnum = letoh32(gh.gh_part_num);
 	if ((secbuf = malloc(dl->d_secsize)) == NULL)
```