# partial MOVE entry read crosses data boundary

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`libelf/gelf_move.c:73`

## Summary

`gelf_getmove()` accepted a truncated `Elf_Data` buffer for an `SHT_MOVE` section when `ndx == 0` and `d_size` was nonzero but smaller than one MOVE entry. The existing bounds check verified only the starting offset, not that the full `Elf32_Move` or `Elf64_Move` entry was present before copying fields into `dst`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A consumer calls `gelf_getmove()` on attacker-controlled `SHT_MOVE` data.
- The `Elf_Data` object is partial, such as data returned by `elf_rawdata()` or otherwise constructed with `d_size < sizeof(MOVE entry)`.
- The requested index is valid as a nonnegative integer, commonly `ndx == 0`.

## Proof

For a crafted `SHT_MOVE` section with a nonzero truncated size smaller than one MOVE entry:

- `gelf_getmove()` verifies that the containing section type maps to `ELF_T_MOVE`.
- `_libelf_msize(ELF_T_MOVE, ec, e->e_version)` returns the required MOVE entry size as `msz`.
- The old check was:

```c
if (msz * (size_t) ndx >= d->d_data.d_size)
```

For `ndx == 0` and `0 < d_size < msz`, this becomes `0 >= d_size`, which is false.

Execution then reaches:

```c
move32 = (Elf32_Move *) d->d_data.d_buf + ndx;
```

or:

```c
move64 = (Elf64_Move *) d->d_data.d_buf + ndx;
```

and copies a complete MOVE entry from a buffer that may contain only one attacker-controlled byte.

The reproduced path confirmed:

- `elf_rawdata()` can create `Elf_Data` pointing at truncated raw section bytes with `d_size = sh_size`.
- `gelf_getmove()` does not reject raw `ELF_T_BYTE` data once the section type maps to `ELF_T_MOVE`.
- The out-of-bounds read occurs during the `Elf32_Move` field copies or the `Elf64_Move` structure assignment.

## Why This Is A Real Bug

The old guard checked whether the start offset of the requested entry was within the buffer. It did not check whether the entire entry fit. C structure field reads and structure assignment require the full `Elf32_Move` or `Elf64_Move` object to be readable. With truncated raw section data, this permits a read beyond the `Elf_Data` boundary and may crash an ELF consumer processing an attacker-supplied object.

The normal translated `elf_getdata()` path may reject non-multiple section sizes, but the reproduced trigger through `elf_rawdata()` or equivalent partial `Elf_Data` remains valid.

## Fix Requirement

Require that the requested entry index fits as a complete MOVE entry within `d_size`, using overflow-safe arithmetic equivalent to:

```c
(ndx + 1) * msz <= d_size
```

## Patch Rationale

The patch replaces multiplication of `msz * ndx` with a division-based bound:

```c
if ((size_t) ndx >= d->d_data.d_size / msz)
```

This rejects any index that does not have a complete `msz`-byte entry available. It also avoids overflow from multiplying `msz` by `ndx`.

For `0 < d_size < msz`, `d_size / msz` is `0`, so `ndx == 0` is rejected. For complete buffers, valid indexes remain accepted through the last full entry.

## Residual Risk

None

## Patch

```diff
diff --git a/libelf/gelf_move.c b/libelf/gelf_move.c
index ce0780d..c614b87 100644
--- a/libelf/gelf_move.c
+++ b/libelf/gelf_move.c
@@ -72,7 +72,7 @@ gelf_getmove(Elf_Data *ed, int ndx, GElf_Move *dst)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (NULL);
 	}
```