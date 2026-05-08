# unchecked ELF32 section-name table index

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/vmd/loadfile_elf.c:921`

## Summary

`elf32_exec()` allocates and reads `elf->e_shnum` ELF32 section headers, but uses `elf->e_shstrndx` as an index into that allocation before validating that the index is less than `elf->e_shnum`. A malformed ELF32 boot image can set `e_shstrndx` out of range and make `vmd` read past the section-header allocation while processing symbols.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`vmd` loads an attacker-supplied ELF32 kernel image with `LOAD_SYM` enabled.

## Proof

`loadfile_elf()` dispatches `ELFCLASS32` inputs to `elf32_exec()` with `LOAD_ALL`.

In `elf32_exec()`:

- `sz = elf->e_shnum * sizeof(Elf32_Shdr)` sizes the allocation.
- `shp = malloc(sz)` allocates storage for exactly `elf->e_shnum` section headers.
- `gzread(fp, shp, sz)` fills only that allocation.
- Before the patch, `shp[elf->e_shstrndx].sh_size` and `shp[elf->e_shstrndx].sh_offset` were evaluated without checking `elf->e_shstrndx < elf->e_shnum`.

A minimal trigger is an ELF32 file with:

- `e_phnum = 0`
- valid `e_shoff`
- `e_shnum = 1`
- `e_shstrndx = 2` or `65535`

Only one section header is read, then the section-name-table lookup indexes outside the allocated array. With `e_shstrndx = 65535`, the read is roughly 2.5 MiB past a one-header allocation and can fault or abort VM startup.

The attacker-controlled boot-image path is practical for a delegated VM user or owner because `vmctl start -b` accepts a chosen boot image, opens it, and sends the file descriptor to `vmd`.

## Why This Is A Real Bug

The ELF header field `e_shstrndx` is attacker-controlled input. The code trusts it as an array index into `shp`, whose bounds are determined by a separate attacker-controlled field, `e_shnum`. Since no ordering or bounds relationship was enforced before indexing, malformed but parseable ELF32 input can cause a host-side memory-safety violation in the `vmd` VM process while parsing an untrusted boot image.

## Fix Requirement

Reject ELF32 inputs where `elf->e_shstrndx >= elf->e_shnum` before any access to `shp[elf->e_shstrndx]`.

## Patch Rationale

The patch adds the required bounds check immediately after the section-header table is read and before `shp[elf->e_shstrndx]` is first used. On invalid input, it frees `shp` and returns failure, matching the surrounding error-handling style and preventing the out-of-bounds read.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/vmd/loadfile_elf.c b/usr.sbin/vmd/loadfile_elf.c
index 5337204..6cec242 100644
--- a/usr.sbin/vmd/loadfile_elf.c
+++ b/usr.sbin/vmd/loadfile_elf.c
@@ -936,6 +936,10 @@ elf32_exec(gzFile fp, Elf32_Ehdr *elf, u_long *marks, int flags)
 			free(shp);
 			return 1;
 		}
+		if (elf->e_shstrndx >= elf->e_shnum) {
+			free(shp);
+			return 1;
+		}
 
 		shpp = maxp;
 		maxp += roundup(sz, sizeof(Elf32_Addr));
```