# Partial MOVE Entry Write Crosses Data Boundary

## Classification

High-severity out-of-bounds write.

## Affected Locations

`libelf/gelf_move.c:141`

## Summary

`gelf_update_move()` validates only that the start offset of a requested `SHT_MOVE` entry is inside the `Elf_Data` buffer. It does not validate that a complete `Elf32_Move` or `Elf64_Move` entry fits before writing.

For truncated attacker-controlled MOVE data, `ndx == 0` and `d_size < msz` pass the existing check, then the function writes a full MOVE entry past the end of `d_buf`.

## Provenance

Reported and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- A consumer processes attacker-controlled ELF data.
- The ELF contains attacker-controlled `SHT_MOVE` / `SHT_SUNW_move` section data.
- The consumer obtains an `Elf_Data` descriptor for that section, including via `elf_rawdata()`.
- The consumer calls `gelf_update_move(ed, ndx, gm)` on the descriptor.

## Proof

The vulnerable check is:

```c
if (msz * (size_t) ndx >= d->d_data.d_size) {
	LIBELF_SET_ERROR(ARGUMENT, 0);
	return (0);
}
```

This rejects only entries whose starting offset is outside the buffer. It does not prove that `msz` bytes remain.

For `ndx == 0` and `d_size == 1`:

```c
msz * 0 >= 1
0 >= 1
false
```

Execution then reaches a full entry write:

```c
move32 = (Elf32_Move *) d->d_data.d_buf + ndx;

move32->m_value  = gm->m_value;
LIBELF_COPY_U32(move32, gm, m_info);
LIBELF_COPY_U32(move32, gm, m_poffset);
move32->m_repeat  = gm->m_repeat;
move32->m_stride = gm->m_stride;
```

or, for ELF64:

```c
move64 = (Elf64_Move *) d->d_data.d_buf + ndx;

*move64 = *gm;
```

A crafted ELF can set a MOVE section size smaller than one full MOVE entry, such as `sh_size = 1`. When exposed as `Elf_Data`, `d_size` reflects that truncated size while `d_buf` points at the raw section data. Calling `gelf_update_move(ed, 0, gm)` therefore writes beyond the `Elf_Data` boundary.

## Why This Is A Real Bug

The original guard establishes only:

```c
entry_start < d_size
```

The write requires:

```c
entry_start + msz <= d_size
```

Those are not equivalent. A buffer may contain the first byte of an entry without containing the complete entry.

The reproduced case demonstrates this gap with `d_size == 1`, where the start offset is valid but the full `Elf32_Move` or `Elf64_Move` write crosses the buffer boundary. Because the ELF section contents and size can be attacker-controlled, this can corrupt memory in the ELF consumer process and plausibly cause denial of service or worse depending on allocator/layout context.

## Fix Requirement

Before writing, require that the requested entry index fits completely inside the data buffer without multiplication overflow:

```c
(size_t) ndx <= (d_size - msz) / msz
```

Also reject buffers smaller than one MOVE entry before subtracting `msz`.

## Patch Rationale

The patch replaces the start-offset-only check with a complete-entry bounds check:

```diff
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if (d->d_data.d_size < msz ||
+	    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```

This ensures:

- `d_size >= msz`, so at least one complete MOVE entry can fit.
- `d_size - msz` cannot underflow.
- The maximum valid index is computed by division, avoiding `msz * ndx` overflow.
- The selected entry has `msz` bytes available before any field write or struct assignment occurs.

## Residual Risk

None

## Patch

```diff
diff --git a/libelf/gelf_move.c b/libelf/gelf_move.c
index ce0780d..5f77e62 100644
--- a/libelf/gelf_move.c
+++ b/libelf/gelf_move.c
@@ -135,7 +135,8 @@ gelf_update_move(Elf_Data *ed, int ndx, GElf_Move *gm)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if (d->d_data.d_size < msz ||
+	    (size_t) ndx > (d->d_data.d_size - msz) / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (0);
 	}
```