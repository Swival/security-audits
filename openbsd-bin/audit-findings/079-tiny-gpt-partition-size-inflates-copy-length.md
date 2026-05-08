# Tiny GPT Partition Size Inflates Copy Length

## Classification

Out-of-bounds write, high severity, certain confidence.

## Affected Locations

`usr.sbin/installboot/i386_installboot.c:581`

## Summary

`findgptefisys()` trusts the GPT header field `gh_part_size` after validating only the header signature, revision, header size, and header checksum. If an attacker-controlled disk supplies a valid GPT header with `gh_part_size` smaller than `sizeof(struct gpt_partition)`, the computed partition entries per sector is inflated. That inflated value is then used to copy too many `struct gpt_partition` objects into the fixed stack array `gp[NGPTPARTITIONS]`, corrupting the stack before the partition-array checksum can reject the malformed disk.

## Provenance

Reported and reproduced from Swival Security Scanner results: https://swival.dev

## Preconditions

- `installboot` scans attacker-controlled disk contents.
- The disk contains a valid protective MBR.
- The GPT header has a valid signature, revision, header size, and recomputed header checksum.
- The GPT header sets `gh_part_size` to a value smaller than `sizeof(struct gpt_partition)`.

## Proof

The vulnerable path is in `findgptefisys()`:

- The GPT header is copied from disk into `gh`.
- `gh_part_size` is accepted after header checksum validation.
- `ghpartspersec` is computed as `dl->d_secsize / ghpartsize`.
- With a 512-byte sector and `gh_part_size = 1`, `ghpartspersec` becomes `512`.
- The loop then executes:

```c
memcpy(gp + i * ghpartspersec, secbuf,
    ghpartspersec * sizeof(struct gpt_partition));
```

On OpenBSD GPT constants, `sizeof(struct gpt_partition)` is 128 bytes, so this requests a 65,536-byte copy into the automatic `gp[NGPTPARTITIONS]` stack array. The overflow occurs before this later checksum validation:

```c
new_csum = crc32((unsigned char *)&gp, ghpartnum * ghpartsize);
```

Therefore, a malformed but header-checksum-valid GPT can trigger stack corruption during disk parsing.

## Why This Is A Real Bug

The copy length is derived from an attacker-controlled on-disk size field but uses the in-memory `sizeof(struct gpt_partition)` as the unit copied. When `gh_part_size` is smaller than the implementation's GPT partition structure size, `ghpartspersec` no longer reflects how many full in-memory entries fit in a sector. This creates a direct mismatch between attacker-controlled parsing metadata and the fixed destination object size, producing an out-of-bounds stack write before any partition-array checksum prevents further processing.

## Fix Requirement

Reject GPT headers where `gh_part_size` is smaller than `sizeof(struct gpt_partition)` before computing `ghpartspersec` or copying partition entries.

## Patch Rationale

The patch adds an early structural validation of the GPT partition entry size:

```c
if (ghpartsize < sizeof(struct gpt_partition))
    return (-1);
```

This ensures the per-sector entry count cannot be inflated by a sub-structure-size GPT entry length. The existing copy expression then remains bounded by the assumption that each on-disk GPT entry is at least as large as the in-memory structure being copied.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/installboot/i386_installboot.c b/usr.sbin/installboot/i386_installboot.c
index d1830fb..a930967 100644
--- a/usr.sbin/installboot/i386_installboot.c
+++ b/usr.sbin/installboot/i386_installboot.c
@@ -665,6 +665,8 @@ findgptefisys(int devfd, struct disklabel *dl, int *gpartp,
 
 	off = letoh64(gh.gh_part_lba) * dl->d_secsize;
 	ghpartsize = letoh32(gh.gh_part_size);
+	if (ghpartsize < sizeof(struct gpt_partition))
+		return (-1);
 	ghpartspersec = dl->d_secsize / ghpartsize;
 	ghpartnum = letoh32(gh.gh_part_num);
 	if ((secbuf = malloc(dl->d_secsize)) == NULL)
```