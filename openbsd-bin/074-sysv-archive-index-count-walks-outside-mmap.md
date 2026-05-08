# SysV Archive Index Count Walks Outside mmap

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/nm/nm.c:359`

## Summary

`nm -s` trusts the SysV archive index symbol count read from an archive member. A crafted archive can forge this count so `show_symtab()` computes the string table pointer outside the mapped archive member and later prints from that invalid pointer, causing an out-of-bounds read and practical process crash.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The user runs `nm -s` on an attacker-supplied crafted archive.

## Proof

`-s` enables archive map printing through `armap`. While parsing an archive, `show_archive()` records a SysV `/ ` symbol table member and later calls `show_symtab()` once the long-name table is available.

In the vulnerable code, `show_symtab()` maps only the archive member length:

```c
MMAP(symtab, len, PROT_READ, MAP_PRIVATE|MAP_FILE, fileno(fp), off);
```

It then trusts the first 32-bit word as the symbol count:

```c
num = betoh32(*symtab);
strtab = (char *)(symtab + num + 1);
```

A crafted `/ ` member of length 8 can contain count `0x40000000` and one valid member offset. The first `*ps` read can remain in bounds, but `strtab = symtab + num + 1` points far outside the 8-byte mapping. The subsequent print dereferences that attacker-controlled out-of-bounds pointer:

```c
printf("%s in %s\n", strtab, p);
```

This reproduces as a crash/denial of service in `nm -s`.

## Why This Is A Real Bug

The archive index is untrusted file input, but the code uses the embedded count to derive both the offset array bounds and the string table start without validating either against `len`. Because `strlen()` and `%s` operate until a NUL byte is found, an out-of-range `strtab` can read arbitrary unmapped memory and crash the process.

## Fix Requirement

Validate the SysV archive index layout before iterating:

- Ensure the member contains at least the count field.
- Ensure `num` offset entries fit inside the mapped `len`.
- Ensure each symbol string is NUL-terminated before the end of the mapping.
- Avoid `strlen()` on untrusted data unless the terminating NUL has already been found in bounds.

## Patch Rationale

The patch changes the count and table pointers to fixed-width `u_int32_t` values, matching the on-disk 32-bit big-endian SysV archive index fields.

It rejects malformed indexes where `len` cannot contain the count field or where `num` would place offset entries beyond the mapped member:

```c
if (len < sizeof(*symtab))
...
if (num > (len - sizeof(*symtab)) / sizeof(*symtab))
```

It then bounds the string table with:

```c
end = (char *)symtab + len;
```

During iteration, it replaces unbounded `strlen(strtab)` with bounded `memchr(strtab, '\0', end - strtab)`. The loop advances only after finding an in-bounds NUL terminator, preventing both pointer walks and string reads outside the mapping.

Malformed indexes now report `bad archive index`, restore the file position, free allocated memory, unmap the member, and return failure.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/nm/nm.c b/usr.bin/nm/nm.c
index 41b2540..ec7ddd9 100644
--- a/usr.bin/nm/nm.c
+++ b/usr.bin/nm/nm.c
@@ -363,9 +363,10 @@ int
 show_symtab(off_t off, u_long len, const char *name, FILE *fp)
 {
 	struct ar_hdr ar_head;
-	int *symtab, *ps;
-	char *strtab, *p;
-	int num, rval = 0;
+	u_int32_t *symtab, *ps;
+	char *strtab, *p, *end, *eos;
+	u_int32_t num;
+	int rval = 0;
 	int namelen;
 	off_t restore;
 
@@ -383,9 +384,25 @@ show_symtab(off_t off, u_long len, const char *name, FILE *fp)
 	}
 
 	printf("\nArchive index:\n");
+	if (len < sizeof(*symtab)) {
+		warnx("%s: bad archive index", name);
+		rval = 1;
+		goto out;
+	}
 	num = betoh32(*symtab);
+	if (num > (len - sizeof(*symtab)) / sizeof(*symtab)) {
+		warnx("%s: bad archive index", name);
+		rval = 1;
+		goto out;
+	}
+	end = (char *)symtab + len;
 	strtab = (char *)(symtab + num + 1);
-	for (ps = symtab + 1; num--; ps++, strtab += strlen(strtab) + 1) {
+	for (ps = symtab + 1; num > 0; num--, ps++, strtab = eos + 1) {
+		if ((eos = memchr(strtab, '\0', end - strtab)) == NULL) {
+			warnx("%s: bad archive index", name);
+			rval = 1;
+			break;
+		}
 		if (fseeko(fp, betoh32(*ps), SEEK_SET)) {
 			warn("%s: fseeko", name);
 			rval = 1;
@@ -408,6 +425,7 @@ show_symtab(off_t off, u_long len, const char *name, FILE *fp)
 		printf("%s in %s\n", strtab, p);
 	}
 
+out:
 	fseeko(fp, restore, SEEK_SET);
 
 	free(p);
```