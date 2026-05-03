# ELF program headers are read past the header buffer

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`ld.so/library_mquery.c:171`

## Summary

`_dl_tryload_shlib()` reads at most 4096 bytes of an attacker-controlled shared object into the stack buffer `hbuf`, then trusts ELF header fields `e_phoff` and `e_phnum` to locate and iterate the program-header table inside that buffer. Without validating that the full program-header table was actually read into `hbuf`, a malformed `ET_DYN` object can make the dynamic loader read past the stack buffer before the object is mapped, terminating the loading process.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Victim process calls `dlopen()` on an attacker-controlled shared object.

## Proof

The vulnerable path is reachable through:

`dlopen()` -> `_dl_load_shlib()` -> `_dl_tryload_shlib()`

In `_dl_tryload_shlib()`:

- `_dl_read(libfile, hbuf, sizeof(hbuf))` reads only a 4096-byte prefix of the candidate object.
- The buffer is treated as an ELF header after checking only magic, `e_type`, and `e_machine`.
- `phdp = (Elf_Phdr *)(hbuf + ehdr->e_phoff)` computes a program-header pointer from attacker-controlled `e_phoff`.
- `for (i = 0; i < ehdr->e_phnum; i++, phdp++)` iterates attacker-controlled `e_phnum`.
- The loop dereferences `phdp->p_align` and `phdp->p_type` before any bounds check proves the table lies inside `hbuf`.

A malformed attacker-supplied `ET_DYN` object with valid ELF magic and `MACHID`, but oversized `e_phoff` or `e_phnum`, reaches this first program-header scan before mapping. The dynamic loader then reads from an attacker-directed address past `hbuf`; choosing an offset or count that reaches unmapped stack or address space can terminate the victim process during loading.

## Why This Is A Real Bug

The program-header table is untrusted file data. The loader only has the bytes returned by `_dl_read()` available in `hbuf`, yet it derives `phdp` and the loop bound directly from ELF fields controlled by the file. Since no check ensures:

- `e_phoff <= bytes_read`
- `e_phnum * sizeof(Elf_Phdr)` fits without overflow
- `e_phoff + e_phnum * sizeof(Elf_Phdr) <= bytes_read`

the subsequent dereferences can read outside the initialized header buffer. This is an invalid dynamic-loader stack read reachable from a normal `dlopen()` of a hostile shared object.

## Fix Requirement

Validate the ELF program-header table bounds before the first program-header iteration. The loader must reject the object unless the complete table described by `e_phoff` and `e_phnum` is contained within the bytes actually read into `hbuf`.

## Patch Rationale

The patch stores the `_dl_read()` result in `hsize`, rejects files too short to contain an `Elf_Ehdr`, and then verifies that the declared program-header table fits within the bytes read:

```c
if (ehdr->e_phoff > (size_t)hsize || ehdr->e_phnum >
    ((size_t)hsize - ehdr->e_phoff) / sizeof(Elf_Phdr)) {
        _dl_close(libfile);
        _dl_errno = DL_NOT_ELF;
        return(0);
}
```

This formulation avoids additive or multiplicative overflow by subtracting only after proving `e_phoff <= hsize`, then comparing `e_phnum` against the maximum number of complete `Elf_Phdr` entries available in the remaining buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/ld.so/library_mquery.c b/ld.so/library_mquery.c
index 971d975..b607a88 100644
--- a/ld.so/library_mquery.c
+++ b/ld.so/library_mquery.c
@@ -114,6 +114,7 @@ _dl_tryload_shlib(const char *libname, int type, int flags, int nodelete)
 	Elf_Addr relro_addr = 0, relro_size = 0;
 	struct stat sb;
 	char hbuf[4096], *exec_start;
+	ssize_t hsize;
 	size_t exec_size;
 
 #define powerof2(x) ((((x) - 1) & (x)) == 0)
@@ -144,7 +145,12 @@ _dl_tryload_shlib(const char *libname, int type, int flags, int nodelete)
 		return NULL;
 	}
 
-	_dl_read(libfile, hbuf, sizeof(hbuf));
+	hsize = _dl_read(libfile, hbuf, sizeof(hbuf));
+	if (hsize < (ssize_t)sizeof(Elf_Ehdr)) {
+		_dl_close(libfile);
+		_dl_errno = DL_NOT_ELF;
+		return(0);
+	}
 	ehdr = (Elf_Ehdr *)hbuf;
 	if (ehdr->e_ident[0] != ELFMAG0  || ehdr->e_ident[1] != ELFMAG1 ||
 	    ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3 ||
@@ -153,6 +159,12 @@ _dl_tryload_shlib(const char *libname, int type, int flags, int nodelete)
 		_dl_errno = DL_NOT_ELF;
 		return(0);
 	}
+	if (ehdr->e_phoff > (size_t)hsize || ehdr->e_phnum >
+	    ((size_t)hsize - ehdr->e_phoff) / sizeof(Elf_Phdr)) {
+		_dl_close(libfile);
+		_dl_errno = DL_NOT_ELF;
+		return(0);
+	}
 
 	/* Insertion sort */
 #define LDLIST_INSERT(ld) do { \
```