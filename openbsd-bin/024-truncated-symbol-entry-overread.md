# Truncated Symbol Entry Overread

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`libelf/gelf_sym.c:74`

## Summary

`gelf_getsym()` validates only that the selected symbol entry starts within `d_size`. If the backing `Elf_Data` contains a truncated final symbol entry, the start offset for that partial entry passes validation, but the subsequent full `Elf32_Sym` field reads or `Elf64_Sym` copy read past the available data.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A consumer calls `gelf_getsym()` on attacker-controlled symbol data.

## Proof

A malicious ELF can expose raw symbol data with a `SHT_SYMTAB` or `SHT_DYNSYM` section whose size is:

```text
n * sizeof(Elf*_Sym) + r
```

where:

```text
0 < r < sizeof(Elf*_Sym)
```

The reproduced path is:

- `libelf/elf_data.c:109` rejects malformed translated ELF symbol sections whose `sh_size` is not a multiple of the symbol file size.
- `elf_rawdata()` does not enforce symbol entry-size multiples.
- `elf_rawdata()` checks that the section lies within the file and returns `d_size = sh_size` at `libelf/elf_data.c:260` and `libelf/elf_data.c:273`.
- `gelf_getsym()` checks the section header type at `libelf/gelf_sym.c:60`, but does not require `ed->d_type` to be translated symbol data.
- Calling `gelf_getsym(data, n, &sym)` on raw data selects the partial final entry.

Before the patch, the bounds check was:

```c
if (msz * (size_t) ndx >= d->d_data.d_size)
```

For `ndx == n`, `msz * ndx` is the start of the partial tail, which is still less than `d_size`. The function then reads a full symbol entry from that partial tail. With the regular-file mmap path in `libelf/libelf_open.c:194`, placing EOF at a page boundary can make the overread fault and crash the consumer.

## Why This Is A Real Bug

The validation proves only that the first byte of the selected symbol entry is in bounds. The function requires an entire `Elf32_Sym` or `Elf64_Sym` to be readable. For raw attacker-controlled symbol data, `d_size` may include a trailing partial entry, so the old check permits an out-of-bounds read beyond mapped ELF data.

## Fix Requirement

Require the full selected symbol entry to fit within `d_size` using overflow-safe arithmetic equivalent to:

```text
(ndx + 1) * msz <= d_size
```

## Patch Rationale

The patch changes the check to:

```c
if ((size_t) ndx >= d->d_data.d_size / msz)
```

This rejects any `ndx` greater than or equal to the number of complete symbol entries present in `d_size`. Integer division truncates away any partial final entry, so truncated tails are not addressable. This also avoids multiplication overflow because it does not compute `msz * ndx`.

## Residual Risk

None

## Patch

```diff
diff --git a/libelf/gelf_sym.c b/libelf/gelf_sym.c
index 1134e93..c06072c 100644
--- a/libelf/gelf_sym.c
+++ b/libelf/gelf_sym.c
@@ -72,7 +72,7 @@ gelf_getsym(Elf_Data *ed, int ndx, GElf_Sym *dst)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (NULL);
 	}
```