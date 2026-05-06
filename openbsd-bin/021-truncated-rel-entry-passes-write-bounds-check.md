# Truncated REL Entry Passes Write Bounds Check

## Classification

High severity out-of-bounds write.

## Affected Locations

- `libelf/gelf_rel.c:142`

## Summary

`gelf_update_rel()` accepts truncated REL data for index 0 because its bounds check validates only the start offset of the requested entry, not whether a full `Elf32_Rel` or `Elf64_Rel` fits in the buffer. With attacker-controlled REL data of nonzero size smaller than one REL entry, the function writes a complete relocation entry past the end of `d_buf`.

## Provenance

Verified by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Application calls `gelf_update_rel()` on attacker-controlled REL data.
- The attacker supplies a malformed ELF containing a `SHT_REL` section with `d_size` smaller than one REL entry.
- The application updates relocation index 0.

## Proof

The reproduced path shows the bug is reachable through `elf_rawdata()`:

- `elf_getdata()` blocks some malformed sections via `sh_size % fsz` validation in `libelf/elf_data.c:109`.
- `elf_rawdata()` does not require section size to be a multiple of REL entry size; it checks only that section offset and size are inside the file.
- `elf_rawdata()` then sets `d_buf` and `d_size` from attacker-controlled section header values in `libelf/elf_data.c:259` and `libelf/elf_data.c:269`.
- `gelf_update_rel()` validates only that the containing section type is `SHT_REL` in `libelf/gelf_rel.c:127`.
- It computes the REL entry memory size, then checks only `msz * ndx >= d->d_data.d_size` in `libelf/gelf_rel.c:137`.
- For `ndx == 0` and `d_size == 1`, the check evaluates as `0 >= 1`, which is false, so execution continues.
- The function then writes a full `Elf32_Rel` through `rel32` fields in `libelf/gelf_rel.c:145` and `libelf/gelf_rel.c:152`, or a full `Elf64_Rel` via `*rel64 = *dr` in `libelf/gelf_rel.c:158`.

A malformed attacker-supplied ELF with a `SHT_REL` section of size 1 can therefore trigger a write past the relocation data buffer when an application updates relocation 0.

## Why This Is A Real Bug

The existing check proves only that the computed entry start offset is inside the data buffer. It does not prove that `msz` bytes are available from that offset. For index 0, every nonzero truncated buffer smaller than `msz` passes the check, and the subsequent write stores a complete relocation entry. This creates attacker-triggered memory corruption, with at least denial-of-service impact and potentially broader corruption when the backing buffer is writable.

## Fix Requirement

Reject updates unless the data buffer contains at least one complete REL entry and the requested index fits entirely within the buffer:

- Require `d_size >= msz`.
- Require `ndx <= (d_size - msz) / msz`.

## Patch Rationale

The patch replaces the start-offset-only check with a full-entry bounds check:

```diff
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if (d->d_data.d_size < msz ||
+	    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```

This prevents truncated buffers from passing for `ndx == 0` and avoids multiplication overflow by subtracting `msz` only after confirming `d_size >= msz`.

## Residual Risk

None

## Patch

`021-truncated-rel-entry-passes-write-bounds-check.patch` patches `libelf/gelf_rel.c`:

```diff
diff --git a/libelf/gelf_rel.c b/libelf/gelf_rel.c
index 8058630..9af6433 100644
--- a/libelf/gelf_rel.c
+++ b/libelf/gelf_rel.c
@@ -134,7 +134,8 @@ gelf_update_rel(Elf_Data *ed, int ndx, GElf_Rel *dr)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if (d->d_data.d_size < msz ||
+	    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```