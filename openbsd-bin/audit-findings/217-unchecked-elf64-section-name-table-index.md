# unchecked ELF64 section-name table index

## Classification

- Type: out-of-bounds read
- Severity: medium
- Confidence: certain

## Affected Locations

- `usr.sbin/vmd/loadfile_elf.c:697`
- `usr.sbin/vmd/loadfile_elf.c:725`
- `usr.sbin/vmd/loadfile_elf.c:727`

## Summary

`elf64_exec()` reads `elf->e_shnum` ELF64 section headers into a heap allocation sized exactly for that count, then indexes `shp[elf->e_shstrndx]` without validating that `e_shstrndx < e_shnum`. A crafted ELF64 boot image can set `e_shstrndx` outside the parsed section-header table and cause `vmd` to read past the allocation while loading symbols.

## Provenance

- Reported by Swival Security Scanner: https://swival.dev
- Finding reproduced and patched from the verified issue data.

## Preconditions

- `vmd` loads an attacker-supplied ELF64 kernel.
- `LOAD_SYM` is enabled; `loadfile_elf()` dispatches ELF64 images to `elf64_exec()` with `LOAD_ALL`.
- The attacker can supply a VM boot image, for example through `vmctl start -b`.

## Proof

`elf64_exec()` calculates:

```c
sz = elf->e_shnum * sizeof(Elf64_Shdr);
shp = malloc(sz);
```

It then reads exactly `sz` bytes of section headers into `shp`.

Before the patch, it immediately used the untrusted section-name string-table index:

```c
size_t shstrsz = shp[elf->e_shstrndx].sh_size;
...
gzseek(fp, (off_t)shp[elf->e_shstrndx].sh_offset, SEEK_SET)
```

A minimal malformed ELF64 trigger has:

- Valid ELF magic and `ELFCLASS64`.
- `e_shnum = 1`.
- `e_shstrndx = 0xffff`.
- `e_phnum = 0` or a benign non-load program header.

The allocation contains one `Elf64_Shdr`, but the loader reads `shp[65535]`.

## Why This Is A Real Bug

`e_shstrndx` is attacker-controlled ELF metadata. The allocation size is derived from `e_shnum`, not from `e_shstrndx`. Without a bounds check, `shp[elf->e_shstrndx]` can address memory well beyond the heap allocation. In the VM boot path this can fault the VM loader process and cause a denial of service during VM startup.

## Fix Requirement

Reject ELF64 images when `elf->e_shstrndx >= elf->e_shnum` before any access to `shp[elf->e_shstrndx]`.

## Patch Rationale

The patch adds the missing bounds check immediately after section headers are successfully read and before the first indexed access using `e_shstrndx`. On failure it frees `shp` and returns an error, matching the existing error-handling style in `elf64_exec()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/loadfile_elf.c b/usr.sbin/vmd/loadfile_elf.c
index 5337204..d8833fa 100644
--- a/usr.sbin/vmd/loadfile_elf.c
+++ b/usr.sbin/vmd/loadfile_elf.c
@@ -718,6 +718,10 @@ elf64_exec(gzFile fp, Elf64_Ehdr *elf, u_long *marks, int flags)
 			free(shp);
 			return 1;
 		}
+		if (elf->e_shstrndx >= elf->e_shnum) {
+			free(shp);
+			return 1;
+		}
 
 		shpp = maxp;
 		maxp += roundup(sz, sizeof(Elf64_Addr));
```