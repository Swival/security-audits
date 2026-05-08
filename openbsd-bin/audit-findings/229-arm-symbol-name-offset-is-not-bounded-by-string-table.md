# ARM symbol name offset is not bounded by string table

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/gprof/elf.c:153`

## Summary

On ARM builds, `gprof` trusts attacker-controlled ELF symbol `st_name` offsets before dereferencing the linked string table. A crafted ELF can place an `STT_FUNC` symbol name offset outside the associated string table, causing `wantsym()` to read out of bounds while filtering ARM mapping symbols. This can crash `gprof` when a user analyzes the malicious file.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `gprof` runs on an ARM build.
- A user invokes `gprof` on an attacker-supplied ELF file.
- The ELF contains a valid-enough section header table and `SHT_SYMTAB`.
- The symbol table links to a string table whose offset is inside the mapped file.
- A processed `STT_FUNC` symbol has `st_name` outside the linked string table bounds.

## Proof

`getnfile()` maps the input ELF and locates the symbol table and linked string table. It checks that `sh_strtab->sh_offset < s.st_size`, but it does not check `sh_strtab->sh_size` against the file size and does not verify each symbol's `st_name` offset before use.

The symbol loop processes attacker-controlled `SHT_SYMTAB` entries and passes them to `wantsym()`:

- `usr.bin/gprof/elf.c:94` checks only selected table metadata.
- `usr.bin/gprof/elf.c:100` derives `strtab` from `sh_strtab->sh_offset`.
- `usr.bin/gprof/elf.c:102` calls `wantsym(&symtab[i], strtab)`.

On ARM, `wantsym()` computes `strtab + sym->st_name` and immediately reads `c[0]`:

- `usr.bin/gprof/elf.c:150` extracts the symbol type.
- `usr.bin/gprof/elf.c:157` computes the name pointer.
- `usr.bin/gprof/elf.c:160` dereferences the pointer.

A crafted function symbol with `st_name` beyond the intended string table, and potentially beyond the mapped file, therefore triggers an out-of-bounds mapped-file read and can crash the `gprof` process.

## Why This Is A Real Bug

The attacker controls the ELF file passed to `gprof`, including symbol table entries and `st_name` values. The code treats `st_name` as a valid offset into the linked string table without checking it against `sh_strtab->sh_size`. On ARM, this unchecked offset is dereferenced even before the symbol name is stored or printed. Invalid ELF input is expected to be rejected safely, not to cause memory reads outside the declared table or process crashes.

## Fix Requirement

Validate that every symbol name offset is less than the linked string table size before any expression of the form `strtab + sym->st_name` is dereferenced or retained as a symbol name.

## Patch Rationale

The patch changes `wantsym()` to accept the string table size and reject symbols whose `st_name` is outside the table:

```c
sym->st_name >= strtabsz
```

`getnfile()` now passes `sh_strtab->sh_size` into both `wantsym()` call sites: the initial count pass and the later population pass. This ensures the same validation is applied before the ARM mapping-symbol filter dereferences `c[0]` and before accepted symbol names are assigned from `strtab + sym->st_name`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/gprof/elf.c b/usr.bin/gprof/elf.c
index 3233608..1c594e8 100644
--- a/usr.bin/gprof/elf.c
+++ b/usr.bin/gprof/elf.c
@@ -39,7 +39,7 @@
 
 #include "gprof.h"
 
-static bool wantsym(const Elf_Sym *, const char *);
+static bool wantsym(const Elf_Sym *, const char *, size_t);
 
 /* Things which get -E excluded by default. */
 static char	*excludes[] = { ".mcount", "_mcleanup", NULL };
@@ -102,7 +102,7 @@ getnfile(const char *filename, char ***defaultEs)
     /* Count the symbols that we're interested in. */
     nname = 0;
     for (i = 1;  i < symtabct;  i++)
-	if (wantsym(&symtab[i], strtab))
+	if (wantsym(&symtab[i], strtab, sh_strtab->sh_size))
 	    nname++;
 
 #ifdef DEBUG
@@ -121,7 +121,7 @@ getnfile(const char *filename, char ***defaultEs)
     for (i = 1;  i < symtabct;  i++) {
 	const Elf_Sym *sym = &symtab[i];
 
-	if (wantsym(sym, strtab)) {
+	if (wantsym(sym, strtab, sh_strtab->sh_size)) {
 	    npe->value = sym->st_value;
 	    npe->name = strtab + sym->st_name;
 #ifdef DEBUG
@@ -139,7 +139,7 @@ getnfile(const char *filename, char ***defaultEs)
 }
 
 static bool
-wantsym(const Elf_Sym *sym, const char *strtab)
+wantsym(const Elf_Sym *sym, const char *strtab, size_t strtabsz)
 {
     int type;
     int bind;
@@ -147,7 +147,8 @@ wantsym(const Elf_Sym *sym, const char *strtab)
     type = ELF_ST_TYPE(sym->st_info);
     bind = ELF_ST_BIND(sym->st_info);
 
-    if (type != STT_FUNC || (aflag && bind == STB_LOCAL))
+    if (type != STT_FUNC || (aflag && bind == STB_LOCAL) ||
+      sym->st_name >= strtabsz)
 #if 0
  ||
       (uflag && strchr(strtab + sym->st_name, '.') != NULL))
```