# Unchecked ELF Relocation Type Indexes Static Tables

## Classification

- Type: out-of-bounds read
- Severity: medium
- Confidence: certain
- Component: sparc64 dynamic linker relocation handling

## Affected Locations

- `ld.so/sparc64/rtld_machine.c:259`
- `ld.so/sparc64/rtld_machine.c:167`
- `ld.so/sparc64/rtld_machine.c:250`
- `ld.so/sparc64/rtld_machine.c:257`
- `ld.so/sparc64/rtld_machine.c:304`
- `ld.so/sparc64/rtld_machine.c:309`

## Summary

`_dl_md_reloc()` derives a relocation `type` from attacker-controlled ELF relocation metadata and uses it as an index into static relocation metadata tables before validating that the type is within bounds. A crafted sparc64 ELF object can provide an out-of-range relocation type, causing deterministic out-of-bounds reads in the dynamic linker before application code runs.

## Provenance

- Verified by reproduction and patch review.
- Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions

- The dynamic linker processes attacker-controlled ELF relocation entries on sparc64.
- A lower-privileged local user can supply or influence loading of a crafted ELF object.
- The crafted relocation has an out-of-range `r_info` relocation type, for example `0xffffffff`.

## Proof

`_dl_md_reloc()` reads relocation entries from `object->Dyn.info[rel]` and computes:

```c
type = ELF_R_TYPE(relas->r_info);
```

Before the patch, only two relocation types were skipped:

```c
if (type == R_TYPE(NONE) || type == R_TYPE(JMP_SLOT))
	continue;
```

No bounds check existed before macro use. The first unsafe access occurs through:

```c
#define RELOC_USE_ADDEND(t) ((reloc_target_flags[t] & _RF_A) != 0)
```

and is reached by:

```c
if (RELOC_USE_ADDEND(type))
	value = relas->r_addend;
```

Later relocation processing also indexes static tables through:

```c
RELOC_RESOLVE_SYMBOL(type)
RELOC_VALUE_BITMASK(type)
RELOC_VALUE_RIGHTSHIFT(type)
RELOC_UNALIGNED(type)
RELOC_TARGET_SIZE(type)
```

These macros index `reloc_target_flags[type]` and `reloc_target_bitmask[type]`. The static tables end at the supported SPARC relocation entries, including `UA16`; an out-of-range `type` is not constrained to those table lengths. Therefore a crafted relocation type such as `0xffffffff` passes the skip check and causes an out-of-bounds table read during dynamic linker relocation processing.

## Why This Is A Real Bug

The relocation type is derived from ELF metadata supplied by the loaded object, not from a trusted internal enum. The code uses that value directly as an array index into fixed-size static tables. The reproduced control flow confirms that unsupported relocation types are not rejected before the first macro access. This creates a deterministic memory-safety failure in `ld.so` while processing an attacker-controlled object, with practical denial-of-service impact.

## Fix Requirement

Reject relocation types that are outside both static relocation metadata table bounds before any macro or table access using `type`.

## Patch Rationale

The patch adds an explicit bounds check immediately after extracting `type` and before the existing `NONE` / `JMP_SLOT` skip logic:

```c
if (type >= nitems(reloc_target_flags) ||
    type >= nitems(reloc_target_bitmask))
	_dl_die("relocation error %d idx %ld", type, i);
```

This ensures every later use of `type` through relocation macros is within both `reloc_target_flags` and `reloc_target_bitmask`. Terminating relocation processing via `_dl_die()` is appropriate because an out-of-range relocation type is invalid input for this architecture-specific relocation implementation.

## Residual Risk

None

## Patch

```diff
diff --git a/ld.so/sparc64/rtld_machine.c b/ld.so/sparc64/rtld_machine.c
index 71b48d6..6cfe587 100644
--- a/ld.so/sparc64/rtld_machine.c
+++ b/ld.so/sparc64/rtld_machine.c
@@ -242,6 +242,10 @@ _dl_md_reloc(elf_object_t *object, int rel, int relasz)
 
 		type = ELF_R_TYPE(relas->r_info);
 
+		if (type >= nitems(reloc_target_flags) ||
+		    type >= nitems(reloc_target_bitmask))
+			_dl_die("relocation error %d idx %ld", type, i);
+
 		if (type == R_TYPE(NONE) || type == R_TYPE(JMP_SLOT))
 			continue;
```
