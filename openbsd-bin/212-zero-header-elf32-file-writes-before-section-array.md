# zero-header Elf32 file writes before section array

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/mopd/common/file.c:634`

## Summary

`GetElf32FileInfo()` accepts an Elf32 header with `e_phnum == 0`. It copies that value into `dl->e_nsec`, skips the program-header loop, then computes padding using `dl->e_sections[dl->e_nsec - 1]`. With `dl->e_nsec == 0`, this indexes `e_sections[-1]` and writes before the fixed section array.

## Provenance

Verified from the reproduced finding and patched source. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

`mopd` loads an attacker-controlled Elf32 boot file.

## Proof

A minimal Elf32 file with valid ELF magic, `EI_CLASS = ELFCLASS32`, valid `EI_DATA`, and `e_phnum = 0` reaches `GetElf32FileInfo()` through the normal boot-file path:

`mopProcessDL()` opens the requested file, `mopStartLoad()` calls `GetFileInfo()`, and `GetFileInfo()` dispatches ELF files to `GetElf32FileInfo()`.

Inside `GetElf32FileInfo()`:

```c
if (e_phnum > SEC_MAX)
	return(-1);
dl->e_nsec = e_phnum;
for (i = 0; i < dl->e_nsec; i++) {
	...
}
dl->e_sections[dl->e_nsec - 1].s_pad =
    dl->e_sections[dl->e_nsec - 1].s_msize -
    dl->e_sections[dl->e_nsec - 1].s_fsize;
```

When `e_phnum == 0`, `dl->e_nsec` is zero, the loop is skipped, and `dl->e_sections[-1].s_pad` is written.

## Why This Is A Real Bug

`e_sections` is a fixed `SEC_MAX` array in `struct dllist`. Indexing `-1` accesses memory before the array, corrupting adjacent `dllist` storage and invoking undefined behavior. Under the stated precondition, a lower-privileged local user controlling a served boot image can trigger daemon memory corruption, causing a crash or altered behavior.

## Fix Requirement

Reject Elf32 files with zero program headers before assigning `e_phnum` to `dl->e_nsec` or using `dl->e_sections`.

## Patch Rationale

The patch extends the existing upper-bound validation to also enforce a nonzero program-header count:

```c
if (e_phnum == 0 || e_phnum > SEC_MAX)
	return(-1);
```

This preserves the existing `SEC_MAX` bound while ensuring later accesses to `dl->e_sections[dl->e_nsec - 1]` and `dl->e_sections[0]` are valid for the accepted range.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/mopd/common/file.c b/usr.sbin/mopd/common/file.c
index 12a9285..2bd3698 100644
--- a/usr.sbin/mopd/common/file.c
+++ b/usr.sbin/mopd/common/file.c
@@ -564,7 +564,7 @@ GetElf32FileInfo(struct dllist *dl, int info)
 		return(-1);
 	}
 
-	if (e_phnum > SEC_MAX)
+	if (e_phnum == 0 || e_phnum > SEC_MAX)
 		return(-1);
 	dl->e_nsec = e_phnum;
 	for (i = 0; i < dl->e_nsec; i++) {
```