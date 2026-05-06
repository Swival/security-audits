# truncated REL entry passes read bounds check

## Classification

Denial of service, medium severity.

## Affected Locations

`libelf/gelf_rel.c:77`

## Summary

`gelf_getrel()` validates only the starting offset of a requested REL entry. For `ndx == 0`, any non-empty truncated REL section with `d_size < sizeof(Elf{32,64}_Rel)` passes the check, after which the function reads a complete relocation entry from insufficient backing data. A malformed attacker-controlled ELF file can therefore cause an out-of-bounds read and process crash in consumers that call `gelf_getrel()` on raw REL data.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- An application parses attacker-controlled ELF input.
- The application obtains raw REL section data, for example through `elf_rawdata()`.
- The application calls `gelf_getrel(ed, ndx, dst)` on that data.
- The REL section is truncated such that `0 < d_size < _libelf_msize(ELF_T_REL, ec, version)`.

## Proof

`gelf_getrel()` computes the REL entry size in `msz`, then checks:

```c
if (msz * (size_t) ndx >= d->d_data.d_size)
```

For `ndx == 0` and a truncated but non-empty REL section, this becomes:

```c
if (0 >= d_size)
```

When `d_size` is 1, the condition is false, so execution continues.

The function then reads a full relocation entry:

```c
rel32 = (Elf32_Rel *) d->d_data.d_buf + ndx;
dst->r_offset = (Elf64_Addr) rel32->r_offset;
```

or, for ELF64:

```c
rel64 = (Elf64_Rel *) d->d_data.d_buf + ndx;
*dst = *rel64;
```

The reproducer confirmed that a one-byte raw `SHT_REL` section passed to `gelf_getrel(d, 0, ...)` triggers an ASan-detected read of 16 bytes at `libelf/gelf_rel.c:92`.

## Why This Is A Real Bug

The existing check proves only that the entry start offset is inside `d_size`; it does not prove that the complete entry is inside `d_size`.

For index zero, the start offset is always zero, so any non-zero truncated section passes. The subsequent `Elf32_Rel` or `Elf64_Rel` load copies fields beyond the available relocation data. Because the data can originate from attacker-controlled ELF section headers and raw file contents, this is a practical malformed-file crash condition for consumers that process untrusted ELF files.

## Fix Requirement

`gelf_getrel()` must reject any index whose complete REL entry is not contained in the data buffer.

The check must enforce:

```c
(ndx + 1) * msz <= d_size
```

using overflow-safe arithmetic.

## Patch Rationale

The patch replaces multiplication of the index by `msz` with division of the buffer size by `msz`:

```diff
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
```

This is overflow-safe because it avoids computing `msz * ndx`.

`d->d_data.d_size / msz` is the number of complete REL entries available in the buffer. If `ndx` is greater than or equal to that count, the requested entry is incomplete or out of bounds and is rejected.

For a truncated one-byte ELF64 REL section, `d_size / msz` is `0`, so `ndx == 0` is rejected before the full-entry read.

## Residual Risk

None

## Patch

`020-truncated-rel-entry-passes-read-bounds-check.patch`

```diff
diff --git a/libelf/gelf_rel.c b/libelf/gelf_rel.c
index 8058630..a52710b 100644
--- a/libelf/gelf_rel.c
+++ b/libelf/gelf_rel.c
@@ -72,7 +72,7 @@ gelf_getrel(Elf_Data *ed, int ndx, GElf_Rel *dst)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (NULL);
 	}
```