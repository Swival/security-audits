# ELF without load segments dereferences null load list

## Classification

Denial of service, medium severity.

## Affected Locations

`ld.so/library_mquery.c:332`

## Summary

`_dl_tryload_shlib()` accepts an `ET_DYN` ELF object, builds its load list only from `PT_LOAD` program headers, and then unconditionally evaluates `LOFF`, which dereferences `lowld`. An attacker-supplied shared object with no `PT_LOAD` headers leaves `lowld == NULL`, causing the dynamic loader to crash the victim process during `dlopen()`.

## Provenance

Verified and reproduced from the supplied finding. Scanner provenance: [Swival Security Scanner](https://swival.dev).

Confidence: certain.

## Preconditions

A victim process calls `dlopen()` on an attacker-supplied `ET_DYN` object.

## Proof

`_dl_tryload_shlib()` accepts the file after checking the ELF magic, `e_type == ET_DYN`, and `e_machine == MACHID`.

The load list is populated only inside the `PT_LOAD` case:

`ld.so/library_mquery.c:226`

If `e_phnum == 0`, or if the program header table contains no `PT_LOAD` entries, both load-list loops are skipped and `lowld` remains `NULL`.

`LOFF` is defined as:

```c
#define LOFF ((Elf_Addr)lowld->start - lowld->moff)
```

Later code evaluates `LOFF` unconditionally, including:

- `_dl_islibc(dynp, LOFF)` at `ld.so/library_mquery.c:334`
- `_dl_pin(..., lowld->start, ...)` at `ld.so/library_mquery.c:336`
- `_dl_finalize_object(..., lowld->start, ..., LOFF)` at `ld.so/library_mquery.c:343`

Reachability from `dlopen()` is source-supported: `dlopen()` calls `_dl_load_shlib()` in `ld.so/dlfcn.c:91`, which resolves a path and calls `_dl_tryload_shlib()` in `ld.so/library_subr.c:427`.

A matching-architecture `ET_DYN` ELF with no `PT_LOAD` program headers therefore reaches a null `lowld` dereference in the dynamic loader and terminates the loading process.

## Why This Is A Real Bug

An `ET_DYN` file without loadable segments is malformed for this loader path, but the function does not reject it before using state that can only be initialized by `PT_LOAD` processing. The crash occurs before graceful error handling, so attacker-controlled input to `dlopen()` can reliably terminate the victim process.

## Fix Requirement

Reject `ET_DYN` objects that produce no load-list entries before any use of `LOFF` or `lowld->start`.

## Patch Rationale

The patch adds an explicit `lowld == NULL` check immediately after program-header parsing and before `LOFF` is defined or evaluated. On malformed input, the loader now closes the file, sets `_dl_errno = DL_CANT_LOAD_OBJ`, and returns failure instead of dereferencing `NULL`.

This is the narrowest fix because valid objects with at least one loadable segment continue through the existing mapping logic unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/ld.so/library_mquery.c b/ld.so/library_mquery.c
index 971d975..bbdcf30 100644
--- a/ld.so/library_mquery.c
+++ b/ld.so/library_mquery.c
@@ -236,6 +236,12 @@ _dl_tryload_shlib(const char *libname, int type, int flags, int nodelete)
 		}
 	}
 
+	if (lowld == NULL) {
+		_dl_close(libfile);
+		_dl_errno = DL_CANT_LOAD_OBJ;
+		return(0);
+	}
+
 #define LOFF ((Elf_Addr)lowld->start - lowld->moff)
 
 retry:
```