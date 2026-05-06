# BSD Symbol Table Size Check Allows Out-Of-Bounds Read

## Classification

Out-of-bounds read, medium severity.

Confidence: certain.

## Affected Locations

`libelf/libelf_ar.c:344`

## Summary

`_libelf_ar_process_bsd_symtab` validates the BSD archive symbol table array size against the wrong base pointer. After reading `arraysize`, pointer `p` has advanced by `sizeof(long)`, but the original check uses `p0 + arraysize >= end`. A crafted archive can set `arraysize` so the validation passes while the subsequent string-table-size read starts exactly at `end`, causing an out-of-bounds read.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

A libelf consumer processes a BSD `ar` archive symbol table from an attacker-controlled archive.

## Proof

The BSD symbol table parser reads the initial array byte count with:

```c
GET_LONG(p, arraysize);
```

`GET_LONG` copies `sizeof(long)` bytes and advances `p` by `sizeof(long)`.

The vulnerable validation was:

```c
if (arraysize < 0 || p0 + arraysize >= end ||
    ((size_t) arraysize % entrysize != 0))
        goto symtaberror;
```

Because the check uses `p0`, it omits the already-consumed count field. With:

```text
arraysize = e_rawsymtabsz - sizeof(long)
```

and `arraysize` aligned to the ranlib entry size, the check passes because:

```text
p0 + arraysize == end - sizeof(long)
```

The parser then computes:

```c
s = p + arraysize;
GET_LONG(s, strtabsize);
```

Since `p == p0 + sizeof(long)`, this makes:

```text
s == end
```

`GET_LONG(s, strtabsize)` then reads `sizeof(long)` bytes starting at `end`, outside the mapped symbol table.

The reproduction confirmed that a crafted first `__.SYMDEF` archive member reaches this code path and that the same boundary condition can crash with `SIGSEGV` when the read crosses into an unmapped page.

## Why This Is A Real Bug

The parser performs a memory read before proving that the string-table-size field is present. The existing minimum-size check only guarantees two `long` fields exist in the whole symbol table, not that a claimed ranlib array leaves room for the second count field.

An attacker controlling the archive can choose `arraysize` so the ranlib array consumes all remaining bytes after the first count. This causes `GET_LONG` to read past `end`, which can terminate libelf consumers that inspect archive symbols.

## Fix Requirement

Validate that the bytes following the already-read `arraysize` field contain both the ranlib array and the following `sizeof(long)` string-table-size field before calling `GET_LONG(s, strtabsize)`.

Required condition:

```text
p + arraysize + sizeof(long) <= end
```

## Patch Rationale

The patch changes the bounds check from the original symbol-table base pointer `p0` to the current pointer `p`, which already accounts for the consumed initial count field. It also explicitly reserves `sizeof(long)` bytes for the string-table-size field that is read next.

This rejects the crafted boundary case where `p + arraysize == end` before `GET_LONG(s, strtabsize)` can read out of bounds.

## Residual Risk

None.

## Patch

```diff
diff --git a/libelf/libelf_ar.c b/libelf/libelf_ar.c
index 273111a..181198c 100644
--- a/libelf/libelf_ar.c
+++ b/libelf/libelf_ar.c
@@ -345,7 +345,7 @@ _libelf_ar_process_bsd_symtab(Elf *e, size_t *count)
 	 */
 	GET_LONG(p, arraysize);
 
-	if (arraysize < 0 || p0 + arraysize >= end ||
+	if (arraysize < 0 || p + arraysize + sizeof(long) > end ||
 	    ((size_t) arraysize % entrysize != 0))
 		goto symtaberror;
```