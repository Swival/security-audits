# Truncated Symbol Entry Overwrite

## Classification

High severity out-of-bounds write.

## Affected Locations

`libelf/gelf_sym.c:135`

## Summary

`gelf_update_sym()` accepts a symbol index when the selected entry only partially fits in `Elf_Data.d_buf`. The pre-patch bounds check proves only that the entry starts before `d_size`; it does not prove that a complete `Elf32_Sym` or `Elf64_Sym` remains. The subsequent full symbol write can run past the end of the data buffer.

## Provenance

Verified from the supplied source, reproducer summary, and patch.

Scanner provenance: https://swival.dev

Confidence: certain.

## Preconditions

- A consumer calls `gelf_update_sym()` on attacker-controlled symbol data.
- The attacker supplies a malformed ELF symbol section whose data size includes a partial final symbol entry.
- `ndx` selects that partial final entry.

## Proof

The original guard in `gelf_update_sym()` was:

```c
if (msz * (size_t) ndx >= d->d_data.d_size) {
	LIBELF_SET_ERROR(ARGUMENT, 0);
	return (0);
}
```

This accepts any `ndx` where the selected entry offset is less than `d_size`.

For a truncated final entry, `msz * ndx < d_size` can be true while `d_size - (msz * ndx) < msz`. In that case, the code proceeds and writes a complete symbol entry:

```c
sym32 = (Elf32_Sym *) d->d_data.d_buf + ndx;

sym32->st_name  = gs->st_name;
sym32->st_info  = gs->st_info;
sym32->st_other = gs->st_other;
sym32->st_shndx = gs->st_shndx;

LIBELF_COPY_U32(sym32, gs, st_value);
LIBELF_COPY_U32(sym32, gs, st_size);
```

or, for ELF64:

```c
sym64 = (Elf64_Sym *) d->d_data.d_buf + ndx;

*sym64 = *gs;
```

The reproducer confirmed that section data can be exposed with `d_buf = e_rawfile + sh_offset` and `d_size = sh_size` without requiring `sh_size` to be a multiple of the symbol size, allowing this partial-entry condition to reach `gelf_update_sym()`.

## Why This Is A Real Bug

The check `msz * ndx >= d_size` is insufficient because it validates only the starting offset of the selected symbol. A full update writes `msz` bytes of symbol data. If fewer than `msz` bytes remain, the function writes beyond `Elf_Data.d_buf`.

This is attacker-reachable through malformed ELF input in consumers that update symbols on raw section descriptors. The impact is process memory corruption or denial of service.

## Fix Requirement

Before writing, require that the selected symbol entry fully fits in the buffer:

```c
(size_t)ndx <= (d_size - msz) / msz
```

Also reject buffers smaller than one symbol entry.

## Patch Rationale

The patch replaces the start-offset-only check with a remaining-capacity check:

```diff
-if (msz * (size_t) ndx >= d->d_data.d_size) {
+if (d->d_data.d_size < msz ||
+    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 	LIBELF_SET_ERROR(ARGUMENT, 0);
 	return (0);
 }
```

This ensures:

- `d_size >= msz`, so subtracting `msz` cannot underflow.
- `ndx` is no greater than the last index whose complete `msz`-byte entry fits.
- The later `Elf32_Sym` field writes and `Elf64_Sym` assignment cannot overrun due to a truncated final entry.
- Multiplication overflow is avoided by using division-based bounds validation.

## Residual Risk

None

## Patch

`025-truncated-symbol-entry-overwrite.patch`

```diff
diff --git a/libelf/gelf_sym.c b/libelf/gelf_sym.c
index 1134e93..7ff6168 100644
--- a/libelf/gelf_sym.c
+++ b/libelf/gelf_sym.c
@@ -134,7 +134,8 @@ gelf_update_sym(Elf_Data *ed, int ndx, GElf_Sym *gs)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if (d->d_data.d_size < msz ||
+	    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```