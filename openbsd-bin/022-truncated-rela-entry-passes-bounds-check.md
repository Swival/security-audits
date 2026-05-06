# Truncated RELA Entry Passes Bounds Check

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`libelf/gelf_rela.c:75`

## Summary

`gelf_getrela()` accepted a RELA index whose entry started inside `d_size` but whose full `Elf32_Rela` or `Elf64_Rela` record extended past the end of the `Elf_Data` descriptor. A crafted `SHT_RELA` section with a partial trailing entry could therefore cause `gelf_getrela()` to read adjacent process memory into the returned `GElf_Rela`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The ELF input is attacker-controlled.
- The attacker can provide an `SHT_RELA` section whose size ends with a partial trailing RELA entry.
- The victim obtains an `Elf_Data` descriptor for that section, including via `elf_rawdata()`.
- The victim calls `gelf_getrela()` for the partial trailing RELA index.

## Proof

`gelf_getrela()` computes the native RELA entry size in `msz`, then originally checked only:

```c
if (msz * (size_t) ndx >= d->d_data.d_size)
```

This verifies that the requested entry starts before the end of the descriptor, but not that the complete entry fits.

For a descriptor size of `msz * ndx + k`, where `0 < k < msz`, the check passes because the start offset is in bounds. The function then casts:

```c
rela32 = (Elf32_Rela *) d->d_data.d_buf + ndx;
```

or:

```c
rela64 = (Elf64_Rela *) d->d_data.d_buf + ndx;
```

and reads a full RELA structure. The trailing bytes are read past `d->d_data.d_size`.

The reproduced path confirms that `elf_rawdata()` can expose attacker-controlled section data without enforcing entry-size divisibility, while `gelf_getrela()` checks the section type but not whether the raw descriptor length contains only complete RELA entries.

## Why This Is A Real Bug

The original bounds check protects only the first byte of the selected entry. `gelf_getrela()` subsequently reads all fields of `Elf32_Rela` or copies a full `Elf64_Rela`, so a partial trailing entry causes an out-of-bounds read. The copied values are returned to the caller through `dst`, creating practical information-disclosure potential if the caller logs, serializes, compares, or otherwise exposes those relocation fields.

## Fix Requirement

Reject any index unless the complete RELA entry fits in the descriptor, using overflow-safe arithmetic equivalent to:

```c
(ndx + 1) * msz <= d->d_data.d_size
```

## Patch Rationale

The patch replaces multiplication-based start-offset validation with division-based complete-entry validation:

```diff
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
```

Because `msz` is already confirmed nonzero, `d_size / msz` is the number of complete RELA entries in the descriptor. Any `ndx` greater than or equal to that count is invalid, including the index of a partial trailing entry. This also avoids multiplication overflow.

## Residual Risk

None

## Patch

`022-truncated-rela-entry-passes-bounds-check.patch`

```diff
diff --git a/libelf/gelf_rela.c b/libelf/gelf_rela.c
index 90f066e..cd9750e 100644
--- a/libelf/gelf_rela.c
+++ b/libelf/gelf_rela.c
@@ -72,7 +72,7 @@ gelf_getrela(Elf_Data *ed, int ndx, GElf_Rela *dst)
 
 	assert(ndx >= 0);
 
-	if (msz * (size_t) ndx >= d->d_data.d_size) {
+	if ((size_t) ndx >= d->d_data.d_size / msz) {
 		LIBELF_SET_ERROR(ARGUMENT, 0);
 		return (NULL);
 	}
```