# Malformed Symbol Entry Size Causes Out-Of-Bounds Read

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

`usr.bin/ctfconv/elf.c:314`

## Summary

`ctfconv` accepts an ELF `SHT_SYMTAB` whose `sh_entsize` is nonzero but smaller than `sizeof(Elf_Sym)`. It then computes `nsymb` using the attacker-controlled `sh_entsize`, while later indexing the returned symbol table as an `Elf_Sym *`. A crafted relocation can pass the `rsym < nsymb` check and cause `elf_reloc_apply()` to read past the validated symbol table bytes, potentially past the mapped file, crashing `ctfconv`.

## Provenance

Reported and reproduced from Swival Security Scanner findings: https://swival.dev

## Preconditions

- `ctfconv` processes attacker-supplied ELF input.
- The ELF contains a `SHT_SYMTAB` section.
- The ELF contains a `SHT_RELA` or `SHT_REL` relocation section linked to that symbol table.
- The malformed symbol table uses an undersized nonzero `sh_entsize`.

## Proof

A crafted ELF can set `.symtab` to:

- `sh_entsize = 1`
- `sh_size = 2`
- `sh_offset` near EOF

This passes the existing symbol table bounds checks because `sh_size` remains within the file and `sh_entsize` is nonzero.

`elf_getsymtab()` then returns:

- `symtab = (Elf_Sym *)(p + sh->sh_offset)`
- `nsymb = sh->sh_size / sh->sh_entsize`

With the crafted values, `nsymb` becomes `2`, even though no complete `Elf_Sym` entries fit in the validated section bytes.

When `elf_getsection()` loads a debug section, it calls `elf_reloc_apply()` to process relocations. A matching relocation section with `sh_link` pointing to the malformed symtab reaches the relocation loop. The relocation loop only validates:

```c
if (rsym >= nsymb)
	continue;
```

For `rsym = 1`, this check passes. The code then performs:

```c
sym = &symtab[rsym];
value = sym->st_value + rela[j].r_addend;
```

or, for `SHT_REL`:

```c
sym = &symtab[rsym];
value = sym->st_value;
```

Because `symtab[rsym]` advances by `sizeof(Elf_Sym)` while `nsymb` was computed using attacker-controlled `sh_entsize`, the read can occur beyond the validated symtab range and potentially beyond the mmap, causing a crash.

## Why This Is A Real Bug

The validation and access units are inconsistent:

- Validation computes symbol count with `sh_size / sh_entsize`.
- Access treats the data as an array of `Elf_Sym`.
- ELF input controls `sh_entsize`.
- `elf_reloc_apply()` trusts the inflated `nsymb`.

This makes the `rsym < nsymb` guard insufficient. The reproducer confirms a malformed symtab entry size can drive `ctfconv` into an out-of-bounds read during relocation processing.

## Fix Requirement

Require `SHT_SYMTAB` section entries to have exactly `sizeof(Elf_Sym)` before computing `nsymb` or returning an `Elf_Sym *`.

## Patch Rationale

The patch changes the symbol table validation from accepting any nonzero entry size to accepting only the native `Elf_Sym` size:

```c
if (sh->sh_entsize != sizeof(Elf_Sym))
	continue;
```

This aligns the symbol count calculation with the later pointer indexing semantics. After the patch, `nsymb = sh_size / sh_entsize` is computed only when each counted entry is actually a complete `Elf_Sym`, so `rsym < nsymb` correctly bounds `symtab[rsym]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/ctfconv/elf.c b/usr.bin/ctfconv/elf.c
index 043939a..b6a9913 100644
--- a/usr.bin/ctfconv/elf.c
+++ b/usr.bin/ctfconv/elf.c
@@ -141,7 +141,7 @@ elf_getsymtab(const char *p, size_t filesize, const char *shstab,
 		if (sh->sh_size > (filesize - sh->sh_offset))
 			continue;
 
-		if (sh->sh_entsize == 0)
+		if (sh->sh_entsize != sizeof(Elf_Sym))
 			continue;
 
 		if (strncmp(shstab + sh->sh_name, ELF_SYMTAB, snlen) == 0) {
```