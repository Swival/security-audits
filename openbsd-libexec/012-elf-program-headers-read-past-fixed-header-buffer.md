# ELF program headers read past fixed header buffer

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`ld.so/library.c:139`

## Summary

`_dl_tryload_shlib()` reads only 4096 bytes of an ELF shared object into the stack buffer `hbuf`, then trusts attacker-controlled ELF program-header metadata from that buffer. Before the patch, `ehdr->e_phoff` and `ehdr->e_phnum` were used to derive `phdp = (Elf_Phdr *)(hbuf + ehdr->e_phoff)` and iterate program headers without verifying that the table fits inside `hbuf`.

A crafted ET_DYN object can therefore cause the dynamic linker to dereference program-header pointers outside the fixed stack buffer while loading the object.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A victim process loads an attacker-controlled ET_DYN shared object, for example through `dlopen()` or an equivalent dynamic-loading path.

## Proof

`_dl_tryload_shlib()` opens the candidate library, reads `sizeof(hbuf)` bytes into `hbuf`, and casts the buffer to `Elf_Ehdr`:

```c
char hbuf[4096];
Elf_Ehdr *ehdr;
Elf_Phdr *phdp;

_dl_read(libfile, hbuf, sizeof(hbuf));
ehdr = (Elf_Ehdr *)hbuf;
```

It validates only ELF magic, type, and machine:

```c
if (ehdr->e_ident[0] != ELFMAG0  || ehdr->e_ident[1] != ELFMAG1 ||
    ehdr->e_ident[2] != ELFMAG2 || ehdr->e_ident[3] != ELFMAG3 ||
    ehdr->e_type != ET_DYN || ehdr->e_machine != MACHID) {
        ...
}
```

Before the patch, it then directly derived the program-header pointer from attacker-controlled `e_phoff` and looped over attacker-controlled `e_phnum`:

```c
phdp = (Elf_Phdr *)(hbuf + ehdr->e_phoff);
for (i = 0; i < ehdr->e_phnum; i++, phdp++) {
        if (phdp->p_align > 1 && !powerof2(phdp->p_align)) {
                ...
        }

        switch (phdp->p_type) {
        case PT_LOAD:
                ...
        }
}
```

The first dereference of `phdp->p_align` occurs immediately after the unchecked pointer calculation. Later code reads additional fields, including `p_type`, `p_vaddr`, `p_memsz`, `p_filesz`, `p_flags`, and `p_offset`.

An attacker can set valid ELF magic, `ET_DYN`, and the expected machine ID, while choosing `e_phoff` and `e_phnum` so that the computed program-header table lies partially or entirely outside `hbuf`. This causes out-of-bounds stack reads during dynamic linking. The reproduced impact is attacker-triggered denial of service of the loading process.

Reachability is direct through `dlopen()` at `ld.so/dlfcn.c:91`, which calls `_dl_load_shlib()`, then `_dl_tryload_shlib()` at `ld.so/library_subr.c:427`.

## Why This Is A Real Bug

The program-header table is attacker-controlled file data, but the loader treats `e_phoff` and `e_phnum` as trusted bounds into a fixed-size stack buffer. The code only reads 4096 bytes from the file before iterating program headers, so any table location or length outside that buffer is invalid for direct access through `hbuf`.

Because `phdp` is dereferenced before any bounds check, malformed input can make the dynamic linker read outside the stack buffer. This is memory-unsafe behavior in a privileged parsing context and is reachable during normal shared-object loading.

## Fix Requirement

Validate the ELF program-header metadata before computing or iterating `phdp`.

The loader must reject objects when:

- `e_phentsize` does not equal `sizeof(Elf_Phdr)`
- `e_phoff` lies beyond the fixed header buffer
- `e_phnum * sizeof(Elf_Phdr)` does not fit within the remaining bytes of `hbuf`

## Patch Rationale

The patch adds a validation block immediately after the existing ELF identity/type/machine checks and before any program-header iteration:

```c
if (ehdr->e_phentsize != sizeof(Elf_Phdr) ||
    ehdr->e_phoff > sizeof(hbuf) ||
    ehdr->e_phnum > (sizeof(hbuf) - ehdr->e_phoff) / sizeof(Elf_Phdr)) {
        _dl_close(libfile);
        _dl_errno = DL_NOT_ELF;
        return(0);
}
```

This prevents both an out-of-range starting offset and an oversized program-header count. The division form avoids integer overflow in the table-size calculation. Requiring the on-disk program-header entry size to match `Elf_Phdr` also prevents the loader from interpreting differently sized entries with the native structure layout.

Invalid inputs are rejected with `DL_NOT_ELF` before `phdp` is created from untrusted metadata.

## Residual Risk

None

## Patch

`012-elf-program-headers-read-past-fixed-header-buffer.patch`

```diff
diff --git a/ld.so/library.c b/ld.so/library.c
index 9b3e974..db3724c 100644
--- a/ld.so/library.c
+++ b/ld.so/library.c
@@ -150,6 +150,13 @@ _dl_tryload_shlib(const char *libname, int type, int flags, int nodelete)
 		_dl_errno = DL_NOT_ELF;
 		return(0);
 	}
+	if (ehdr->e_phentsize != sizeof(Elf_Phdr) ||
+	    ehdr->e_phoff > sizeof(hbuf) ||
+	    ehdr->e_phnum > (sizeof(hbuf) - ehdr->e_phoff) / sizeof(Elf_Phdr)) {
+		_dl_close(libfile);
+		_dl_errno = DL_NOT_ELF;
+		return(0);
+	}
 
 	_dl_memset(&mut, 0, sizeof mut);
 	_dl_memset(&imut, 0, sizeof imut);
```