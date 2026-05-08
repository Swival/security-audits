# Symbol Table Size Is Not Bounded By Mapped File

## Classification

Denial of service, medium severity.

## Affected Locations

`usr.bin/gprof/elf.c:100`

## Summary

`gprof` maps the input ELF file and locates the `SHT_SYMTAB` section, but the original validation only checked that `sh_offset` was inside the mapped file and that `sh_entsize` was nonzero. It did not check that `sh_offset + sh_size` stayed within the mapped file.

An attacker-provided ELF can set a valid in-file symbol table offset and an oversized `sh_size`. `gprof` then computes an attacker-controlled symbol count and iterates past the end of the mmap, crashing while reading symbol fields.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `gprof` on an attacker-provided ELF file.

## Proof

The reproduced data flow is:

- `usr.bin/gprof/elf.c:98` sets `symtab = base + sh_symtab->sh_offset`.
- `usr.bin/gprof/elf.c:99` computes `symtabct = sh_symtab->sh_size / sh_symtab->sh_entsize`.
- `usr.bin/gprof/elf.c:104` iterates up to `symtabct` and passes `&symtab[i]` to `wantsym()`.
- `usr.bin/gprof/elf.c:147` reads `sym->st_info`.

The existing checks accepted a crafted ELF where:

- `SHT_SYMTAB.sh_offset` was inside the file.
- `SHT_SYMTAB.sh_entsize` was `sizeof(Elf_Sym)`.
- `SHT_SYMTAB.sh_size` was large enough to make `symtabct` extend beyond the mapped file.

A 4096-byte ELF with `sh_offset = 4080` and `sh_size = 24 * 100000000` reproduced the crash in a harness using the committed `usr.bin/gprof/elf.c` body, terminating with `Segmentation fault` / exit `139`.

## Why This Is A Real Bug

The symbol table pointer is derived from the mmap base plus an attacker-controlled section offset. The loop bound is derived from attacker-controlled `sh_size`. Without proving that the full symbol table section lies within `s.st_size`, both symbol-processing loops can dereference memory past the mapped file.

The impact is attacker-triggered termination of the victim's `gprof` process.

## Fix Requirement

Reject symbol table sections whose declared byte range extends beyond the mapped file:

`sh_offset + sh_size <= s.st_size`

The check must avoid integer overflow.

## Patch Rationale

The patch adds a bounds check using subtraction:

```c
sh_symtab->sh_size > s.st_size - sh_symtab->sh_offset
```

This is safe because it is evaluated after checking `sh_symtab->sh_offset >= s.st_size`. Therefore, for accepted offsets, `s.st_size - sh_symtab->sh_offset` is the maximum valid remaining byte count in the mmap. Any larger `sh_size` is rejected before `symtabct` is computed or the symbol table is indexed.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/gprof/elf.c b/usr.bin/gprof/elf.c
index 3233608..91ebc05 100644
--- a/usr.bin/gprof/elf.c
+++ b/usr.bin/gprof/elf.c
@@ -92,6 +92,7 @@ getnfile(const char *filename, char ***defaultEs)
     sh_strtab = &shdrs[sh_symtab->sh_link];
 
     if (sh_symtab->sh_offset >= s.st_size ||
+	sh_symtab->sh_size > s.st_size - sh_symtab->sh_offset ||
 	sh_symtab->sh_entsize == 0 ||
 	sh_strtab->sh_offset >= s.st_size)
 	errx(1, "%s: bad symbol table", filename);
```