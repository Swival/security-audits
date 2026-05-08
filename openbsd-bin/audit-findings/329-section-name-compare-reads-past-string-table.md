# section-name compare reads past string table

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/ctfconv/elf.c:145`

## Summary

`elf_getsection()` validates that `sh_name` starts inside the ELF section-name string table, but it does not validate that the requested comparison length also remains inside that table. A crafted ELF object can place `sh_name` near the end of `shstrtab`, causing `strncmp(shstab + sh->sh_name, sname, snlen)` to read past the validated string table and potentially past the mapped file, crashing `ctfconv`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `ctfconv` processes an attacker-controlled ELF object.
- The ELF object has a valid section table.
- The section-name string table is accepted as inside the file.
- A section header uses `sh_name` near the end of `shstrtab`.

## Proof

`elf_getshstab()` validates that the section-name string table lies inside the file, but it does not require section names to be NUL-terminated within that table.

`elf_getsection()` computes:

```c
snlen = strlen(sname);
```

It then rejects only section names whose start offset is outside the string table:

```c
if ((sh->sh_link >= eh->e_shnum) || (sh->sh_name >= shstabsz))
	continue;
```

Immediately after that, it compares `snlen` bytes:

```c
if (strncmp(shstab + sh->sh_name, sname, snlen) == 0) {
```

A crafted ELF can set `shstrtab` to end at EOF, set `sh_name` to the final byte of that table, and place `'.'` there. During lookup of a name such as `.debug_abbrev`, `strncmp()` matches the first byte and then reads the second byte from one byte past `shstrtab`, potentially outside the mapped file.

The reproducer confirmed the same failing operation with a guard-page runtime test: `strncmp()` from the final accessible byte against `.debug_abbrev` faults when reading the second byte.

## Why This Is A Real Bug

The existing guard proves only that `shstab + sh->sh_name` is a valid starting pointer. It does not prove that `snlen` bytes are readable from that pointer. Since `strncmp()` may read up to `snlen` bytes, an attacker-controlled `sh_name` near the end of `shstrtab` can trigger an out-of-bounds read. Because `ctfconv` processes ELF objects supplied as input, this is reachable as a local denial of service.

## Fix Requirement

Before calling `strncmp()`, require the whole comparison range to fit inside `shstrtab`:

```c
snlen <= shstabsz - sh->sh_name
```

This must be checked after confirming `sh->sh_name < shstabsz` to avoid unsigned underflow.

## Patch Rationale

The patch extends the existing section-name validation in `elf_getsection()`:

```diff
-		if ((sh->sh_link >= eh->e_shnum) || (sh->sh_name >= shstabsz))
+		if ((sh->sh_link >= eh->e_shnum) || (sh->sh_name >= shstabsz) ||
+		    (snlen > shstabsz - sh->sh_name))
 			continue;
```

This preserves existing behavior for valid section names while skipping malformed section headers whose name offset cannot provide `snlen` readable bytes. The subtraction is safe because it is evaluated only after `sh->sh_name >= shstabsz` has been checked in the same short-circuit expression.

## Residual Risk

None

## Patch

`329-section-name-compare-reads-past-string-table.patch`

```diff
diff --git a/usr.bin/ctfconv/elf.c b/usr.bin/ctfconv/elf.c
index 043939a..ecbc188 100644
--- a/usr.bin/ctfconv/elf.c
+++ b/usr.bin/ctfconv/elf.c
@@ -195,7 +195,8 @@ elf_getsection(char *p, size_t filesize, const char *sname, const char *shstab,
 			continue;
 
 		sh = (Elf_Shdr *)(p + shoff);
-		if ((sh->sh_link >= eh->e_shnum) || (sh->sh_name >= shstabsz))
+		if ((sh->sh_link >= eh->e_shnum) || (sh->sh_name >= shstabsz) ||
+		    (snlen > shstabsz - sh->sh_name))
 			continue;
 
 		if (sh->sh_offset > filesize)
```