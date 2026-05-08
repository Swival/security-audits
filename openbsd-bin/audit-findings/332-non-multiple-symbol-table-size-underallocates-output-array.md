# Non-Multiple Symbol Table Size Underallocates Output Array

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/nm/elf.c:458`

## Summary

`nm` accepted ELF symbol table sections whose `sh_size` was not a multiple of `sizeof(Elf_Sym)`. `elf_symloadx` allocated output arrays using the floored symbol count, but iterated while any bytes remained. A positive trailing remainder caused one extra full-symbol read and could write one element past the allocated `*pnames` array.

## Provenance

Verified and patched from the reproduced Swival Security Scanner finding: https://swival.dev

## Preconditions

- Victim runs `nm` on an attacker-supplied crafted ELF file.
- The crafted ELF contains a symbol section named as the loaded symbol table.
- The symbol section `sh_size` is not a multiple of `sizeof(Elf_Sym)`.
- The file contains enough backing bytes for the extra `fread`.
- The extra parsed symbol has a valid nonzero `st_name`.

## Proof

`elf_symloadx` finds the attacker-controlled symbol section by name and copies `shdr[i].sh_size` into `symsize`.

It then computes:

```c
*pnrawnames = symsize / sizeof(sbuf);
```

and allocates `*pnames` and `*psnames` using that floored count.

The later loop runs on bytes remaining, not full entries:

```c
for (np = *pnames; symsize > 0; symsize -= sizeof(sbuf)) {
```

If `symsize` has a positive remainder after division by `sizeof(sbuf)`, the allocation reserves space for only the full entries, but the loop performs one additional iteration. When the extra symbol passes the `st_name` check, `elf2nlist` and subsequent assignments write through `np` past the end of the allocated `*pnames` array.

## Why This Is A Real Bug

The crafted ELF controls `sh_size`, and `nm` reaches `elf_symloadx` through normal file processing. Allocation and iteration use inconsistent interpretations of the same section size: allocation floors to complete symbols, while iteration treats any positive remainder as another symbol. This mismatch produces a deterministic heap out-of-bounds write, with impact ranging from process crash to heap corruption.

## Fix Requirement

Reject symbol table sections whose `sh_size` is not an exact multiple of `sizeof(Elf_Sym)` before allocating output arrays or entering the symbol iteration loop.

## Patch Rationale

The patch validates `symsize` immediately after loading it from the symbol section header:

```c
if (symsize % sizeof(sbuf) != 0) {
	warnx("%s: corrupt file", name);
	if (stab)
		MUNMAP(stab, *pstabsize);
	return (1);
}
```

This enforces ELF symbol entry alignment before the floored count is used for allocation. After this check, `symsize / sizeof(sbuf)` matches the number of loop iterations, so `np` cannot advance past the allocated symbol array due to a trailing partial entry.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/nm/elf.c b/usr.bin/nm/elf.c
index 6bf7f3b..31e2314 100644
--- a/usr.bin/nm/elf.c
+++ b/usr.bin/nm/elf.c
@@ -449,6 +449,12 @@ elf_symloadx(const char *name, FILE *fp, off_t foff, Elf_Ehdr *eh,
 	for (i = 0; i < eh->e_shnum; i++) {
 		if (!strcmp(shstr + shdr[i].sh_name, symtab)) {
 			symsize = shdr[i].sh_size;
+			if (symsize % sizeof(sbuf) != 0) {
+				warnx("%s: corrupt file", name);
+				if (stab)
+					MUNMAP(stab, *pstabsize);
+				return (1);
+			}
 			if (fseeko(fp, foff + shdr[i].sh_offset, SEEK_SET)) {
 				warn("%s: fseeko", name);
 				if (stab)
```