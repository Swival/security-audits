# Unchecked ELF64 Section Name Offset

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.sbin/vmd/loadfile_elf.c:725`

## Summary

`elf64_exec()` trusts attacker-controlled ELF64 section metadata while loading symbols. It indexes the section-name string table with `shp[i].sh_name` and passes the resulting pointer to `strcmp()` without proving that the offset is inside the allocated `shstr` buffer or that the referenced name is NUL-terminated within that buffer. A malformed ELF64 kernel can therefore make `vmd` read beyond the heap allocation during VM kernel loading.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `vmd` loads an attacker-supplied ELF64 kernel image.
- Symbol loading is enabled through `LOAD_SYM`, as in the `LOAD_ALL` path used by `loadfile_elf()`.
- The ELF64 file contains attacker-controlled section headers.
- A section has `sh_name` outside the section-name string table, or points to a non-NUL-terminated byte range within it.

## Proof

`loadfile_elf()` dispatches ELF64 files to `elf64_exec()` with `LOAD_ALL`.

Inside `elf64_exec()`:

- Section headers are read from the file into `shp`.
- The section-name table size is taken from `shp[elf->e_shstrndx].sh_size`.
- `shstr` is allocated with exactly that size and filled from the file.
- The section loop compares section names using:
  - `strcmp(shstr + shp[i].sh_name, ".debug_line")`
  - `strcmp(shstr + shp[i].sh_name, ELF_CTF)`

Before the patch, there was no validation that:

- `elf->e_shstrndx < elf->e_shnum`
- `shp[i].sh_name < shstrsz`
- a NUL byte exists between `shstr + shp[i].sh_name` and `shstr + shstrsz`

The finding was reproduced with a minimal ELF64 and a harness containing the same section-name loop. ASan crashed in `strcmp()` when `sh_name` pointed outside the allocated `shstr` buffer.

## Why This Is A Real Bug

The vulnerable pointer is derived directly from untrusted ELF section headers. `strcmp()` performs an unbounded read until it finds a NUL byte, so an out-of-range or unterminated section name can read past the heap allocation. A far enough `sh_name` can fault, causing denial of service in the loader/VM process.

The relevant section types do not prevent reachability: a malformed non-`SHT_SYMTAB` and non-`SHT_STRTAB` section reaches the `.debug_line` and `ELF_CTF` `strcmp()` checks.

## Fix Requirement

The ELF64 symbol-loading path must reject or safely ignore invalid section-name metadata before string comparison:

- Validate `e_shstrndx` before indexing `shp`.
- Validate each `sh_name` offset against `shstrsz`.
- Ensure the candidate name is NUL-terminated within the allocated `shstr` buffer before calling `strcmp()`.

## Patch Rationale

The patch adds an early `e_shstrndx >= e_shnum` check before reading the section-name table header. This prevents out-of-bounds access to `shp[elf->e_shstrndx]`.

The patch then computes `shname` only when:

- `shp[i].sh_name < shstrsz`
- `memchr()` finds a terminating `'\0'` within the remaining `shstr` allocation

The `strcmp()` calls are gated on `shname != NULL`, so malformed section names no longer produce out-of-bounds reads. Sections selected by type, `SHT_SYMTAB` or `SHT_STRTAB`, preserve existing behavior because they do not require section-name string comparisons.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/loadfile_elf.c b/usr.sbin/vmd/loadfile_elf.c
index 5337204..7522602 100644
--- a/usr.sbin/vmd/loadfile_elf.c
+++ b/usr.sbin/vmd/loadfile_elf.c
@@ -722,6 +722,10 @@ elf64_exec(gzFile fp, Elf64_Ehdr *elf, u_long *marks, int flags)
 		shpp = maxp;
 		maxp += roundup(sz, sizeof(Elf64_Addr));
 
+		if (elf->e_shstrndx >= elf->e_shnum) {
+			free(shp);
+			return 1;
+		}
 		size_t shstrsz = shp[elf->e_shstrndx].sh_size;
 		char *shstr = malloc(shstrsz);
 		if (gzseek(fp, (off_t)shp[elf->e_shstrndx].sh_offset,
@@ -748,10 +752,16 @@ elf64_exec(gzFile fp, Elf64_Ehdr *elf, u_long *marks, int flags)
 				havesyms = 1;
 
 		for (i = 0; i < elf->e_shnum; i++) {
+			char *shname = NULL;
+
+			if (shp[i].sh_name < shstrsz &&
+			    memchr(shstr + shp[i].sh_name, '\0',
+			    shstrsz - shp[i].sh_name) != NULL)
+				shname = shstr + shp[i].sh_name;
 			if (shp[i].sh_type == SHT_SYMTAB ||
 			    shp[i].sh_type == SHT_STRTAB ||
-			    !strcmp(shstr + shp[i].sh_name, ".debug_line") ||
-			    !strcmp(shstr + shp[i].sh_name, ELF_CTF)) {
+			    (shname != NULL && !strcmp(shname, ".debug_line")) ||
+			    (shname != NULL && !strcmp(shname, ELF_CTF))) {
 				if (havesyms && (flags & LOAD_SYM)) {
 					if (gzseek(fp, (off_t)shp[i].sh_offset,
 					    SEEK_SET) == -1) {
```