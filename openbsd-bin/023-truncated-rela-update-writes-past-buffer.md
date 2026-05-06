# truncated RELA update writes past buffer

## Classification

Out-of-bounds write, medium severity. Confidence: certain.

## Affected Locations

`libelf/gelf_rela.c:134`

## Summary

`gelf_update_rela()` validates only that the requested RELA entry starts inside the `Elf_Data` buffer. If the buffer contains a truncated trailing RELA entry, the function accepts the index and then writes a full `Elf32_Rela` or `Elf64_Rela`, extending past `d_data.d_buf`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

An application updates RELA entries from an attacker-controlled ELF, specifically through a raw or custom `Elf_Data` path that can expose a truncated `SHT_RELA` section to `gelf_update_rela()`.

## Proof

The vulnerable bounds check is:

```c
if (msz * (size_t) ndx >= d->d_data.d_size) {
	LIBELF_SET_ERROR(ARGUMENT, 0);
	return (0);
}
```

This rejects only indexes whose starting offset is outside the buffer. It does not require the full entry to fit.

For ELFCLASS64, the function then computes:

```c
rela64 = (Elf64_Rela *) d->d_data.d_buf + ndx;
*rela64 = *dr;
```

With `ndx = 0` and `0 < d_size < sizeof(Elf64_Rela)`, the check passes because the entry starts at offset zero, but the assignment writes a full `Elf64_Rela`. The reproduced ASan harness confirmed a 24-byte write at `libelf/gelf_rela.c:161` past a 1-byte buffer.

The normal translated `elf_getdata()` path rejects malformed RELA sections because `libelf/elf_data.c:109` rejects section sizes where `sh_size % fsz != 0`. A practical path remains through `elf_rawdata()`, which preserves attacker-controlled `sh_size` as `d_size` at `libelf/elf_data.c:269`. `gelf_update_rela()` verifies only that the section type maps to `ELF_T_RELA`; it does not verify that the data type is translated RELA data or that a complete entry fits.

## Why This Is A Real Bug

The function performs a full-structure write after an incomplete bounds check. A truncated `Elf_Data` buffer can therefore cause memory corruption when an application calls `gelf_update_rela()` on attacker-controlled raw/custom RELA data. The issue is independent of parser rejection in the translated data path because raw data can still reach the updater.

## Fix Requirement

Require the complete RELA entry to fit in the buffer using overflow-safe arithmetic equivalent to:

```c
(ndx + 1) * msz <= d_size
```

The check must reject any index where the entry start is inside the buffer but the full entry would extend past it.

## Patch Rationale

The patch changes the check to division-based bounds validation:

```c
if ((size_t) ndx >= d->d_data.d_size / msz) {
	LIBELF_SET_ERROR(ARGUMENT, 0);
	return (0);
}
```

This accepts only indexes strictly below the number of complete entries in the buffer. Because integer division truncates, any partial trailing RELA entry is excluded. The expression also avoids multiplication overflow from `msz * ndx`.

## Residual Risk

None

## Patch

```diff
diff --git a/libelf/gelf_rela.c b/libelf/gelf_rela.c
index 90f066e..0c468a2 100644
--- a/libelf/gelf_rela.c
+++ b/libelf/gelf_rela.c
@@ -135,7 +135,7 @@ gelf_update_rela(Elf_Data *ed, int ndx, GElf_Rela *dr)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```