# Unterminated Section-Name Table Reaches strcmp

## Classification

Out-of-bounds read, low severity.

Confidence: certain.

## Affected Locations

`usr.bin/nm/elf.c:435`

## Summary

`nm` loads the ELF section-name string table into a heap buffer sized exactly to the table length, without appending a NUL terminator. `elf_symloadx()` validates only that each `sh_name` offset is within the table, then passes `shstr + shdr[i].sh_name` to `strcmp()`. If the referenced suffix is not NUL-terminated within the allocated table, `strcmp()` reads past the heap allocation and may crash the `nm` process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

Victim runs `nm` on an attacker-controlled ELF file.

## Proof

`elf_symload()` assigns `shstrsize = shdr[eh->e_shstrndx].sh_size`, allocates exactly `malloc(shstrsize)`, and reads exactly `shstrsize` bytes from the ELF section-name table into `shstr`.

`elf_symloadx()` checks:

```c
if (shdr[i].sh_name >= shstrsize) {
	warnx("%s: corrupt file", name);
	return (1);
}
```

This accepts any offset inside `shstr`, including an offset into a suffix that has no NUL byte before `shstr + shstrsize`.

The accepted pointer is then used as a C string:

```c
if (!strcmp(shstr + shdr[i].sh_name, strtab)) {
```

A crafted section-name table can place `.strtab` as the final 7 bytes of `shstr` without a trailing NUL. The offset points to `.strtab`, passes the bounds check, and causes `strcmp()` to read at least `shstr[shstrsize]` while comparing against the literal terminator.

Reproduction confirmed that this reaches an out-of-bounds heap read in libc `strcmp`; ASan reports a heap-buffer-overflow at the first byte past the allocated region.

## Why This Is A Real Bug

The ELF section-name table is attacker-controlled input when `nm` is run on an untrusted file. The code treats an in-bounds offset as sufficient proof of a valid C string, but C string operations require a terminating NUL before the end of the object. Because `shstr` is allocated at exactly `shstrsize` bytes, `strcmp()` can read outside the allocation when the table suffix is unterminated. This is undefined behavior and can fault at a protected allocation boundary, causing denial of service.

## Fix Requirement

Before any `strcmp()` on `shstr + shdr[i].sh_name`, require a NUL byte within the remaining section-name table range:

```c
shstrsize - shdr[i].sh_name
```

Reject the file as corrupt if no terminator exists.

## Patch Rationale

The patch extends the existing `sh_name` validation in `elf_symloadx()` to verify both:

- the offset is inside `shstr`
- the referenced suffix is NUL-terminated within the allocated table

Using `memchr()` bounds the scan to the remaining bytes in `shstr`, preventing `strcmp()` from seeing an unterminated attacker-controlled buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/nm/elf.c b/usr.bin/nm/elf.c
index 6bf7f3b..373274e 100644
--- a/usr.bin/nm/elf.c
+++ b/usr.bin/nm/elf.c
@@ -429,7 +429,9 @@ elf_symloadx(const char *name, FILE *fp, off_t foff, Elf_Ehdr *eh,
 	int i;
 
 	for (i = 0; i < eh->e_shnum; i++) {
-		if (shdr[i].sh_name >= shstrsize) {
+		if (shdr[i].sh_name >= shstrsize ||
+		    memchr(shstr + shdr[i].sh_name, '\0',
+		    shstrsize - shdr[i].sh_name) == NULL) {
 			warnx("%s: corrupt file", name);
 			return (1);
 		}
```