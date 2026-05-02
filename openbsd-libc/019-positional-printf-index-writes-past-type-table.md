# Positional printf index writes past type table

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

- `stdio/vfprintf.c:596`
- `stdio/vfprintf.c:1158`
- `stdio/vfprintf.c:1165`
- `stdio/vfprintf.c:1253`
- `stdio/vfprintf.c:1486`

## Summary

A positional printf conversion with a very large argument index, such as `%999999$d`, causes `__find_arguments` to write past the allocated `typetable`.

The vulnerable `ADDTYPE` macro grows the table at most once when `nextarg >= tablesize`, then writes `typetable[nextarg++] = type` even if `nextarg` is still outside the newly allocated table.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and patch evidence.

## Preconditions

- An application passes an attacker-controlled string as a printf format.
- The format string contains a positional conversion with a large index, for example `%999999$d`.

## Proof

A positional format such as `%999999$d` reaches `__vfprintf`, which detects the positional `$` syntax and invokes `__find_arguments`.

Inside `__find_arguments`:

- The positional index parser reads `999999`.
- `nextarg` is assigned that attacker-controlled index.
- The parser reaches the conversion type and calls `ADDSARG` / `ADDTYPE`.
- The initial type table has `STATIC_ARG_TBL_SIZE` entries, i.e. 8.
- `ADDTYPE` calls `__grow_type_table` only once when `nextarg >= tablesize`.
- The first growth expands the table only to `getpagesize()`.
- `999999` remains far beyond the new table size.
- `typetable[nextarg++] = type` writes out of bounds.

The reproduced checkout places the vulnerable write at `stdio/vfprintf.c:1165`; the scanner location `stdio/vfprintf.c:952` is offset for this source version.

## Why This Is A Real Bug

The index is attacker-controlled through the format string and is used directly as an array index after insufficient bounds growth.

A single growth from 8 entries to page size does not make an index such as `999999` valid. Because the subsequent write is unconditional, the code corrupts memory in the printf caller process before argument table construction completes.

This gives at least practical denial of service and creates memory corruption risk in any program that incorrectly exposes printf format control to an attacker.

## Fix Requirement

The type table must be grown until `nextarg < tablesize` before writing.

Growth failures must be checked and propagated as errors.

Growth size arithmetic must avoid integer overflow.

Cleanup must unmap the actual type table allocation size.

## Patch Rationale

The patch changes `ADDTYPE` from a single conditional grow to a checked loop:

- Repeatedly calls `__grow_type_table` while `nextarg >= tablesize`.
- Returns `-1` through `ret` and exits cleanup on allocation or overflow failure.
- Updates `tablemax` only after the table is large enough.
- Writes `typetable[nextarg++]` only when the index is in bounds.

The patch also rewrites `ADDSARG` and `ADDUARG` into statement macros so they can safely call the now-control-flowing `ADDTYPE`.

`__grow_type_table` now checks `*tablesize > INT_MAX / 2` before doubling, sets `errno = EOVERFLOW`, and returns failure rather than overflowing `newsize`.

The cleanup path now unmaps `typetable` with `tablesize`, the actual mapped type-table size, instead of `*argtablesiz`, which belongs to the separate argument table.

## Residual Risk

None

## Patch

```diff
diff --git a/stdio/vfprintf.c b/stdio/vfprintf.c
index 7f0e9c1..aee039c 100644
--- a/stdio/vfprintf.c
+++ b/stdio/vfprintf.c
@@ -1158,29 +1158,55 @@ __find_arguments(const char *fmt0, va_list ap, union arg **argtable,
 	/*
 	 * Add an argument type to the table, expanding if necessary.
 	 */
-#define ADDTYPE(type) \
-	((nextarg >= tablesize) ? \
-		__grow_type_table(&typetable, &tablesize) : 0, \
-	(nextarg > tablemax) ? tablemax = nextarg : 0, \
-	typetable[nextarg++] = type)
+#define ADDTYPE(type) do { \
+	while (nextarg >= tablesize) { \
+		if (__grow_type_table(&typetable, &tablesize) == -1) { \
+			ret = -1; \
+			goto finish; \
+		} \
+	} \
+	if (nextarg > tablemax) \
+		tablemax = nextarg; \
+	typetable[nextarg++] = type; \
+} while (0)
 
-#define	ADDSARG() \
-        ((flags&MAXINT) ? ADDTYPE(T_MAXINT) : \
-	    ((flags&PTRINT) ? ADDTYPE(T_PTRINT) : \
-	    ((flags&SIZEINT) ? ADDTYPE(T_SSIZEINT) : \
-	    ((flags&LLONGINT) ? ADDTYPE(T_LLONG) : \
-	    ((flags&LONGINT) ? ADDTYPE(T_LONG) : \
-	    ((flags&SHORTINT) ? ADDTYPE(T_SHORT) : \
-	    ((flags&CHARINT) ? ADDTYPE(T_CHAR) : ADDTYPE(T_INT))))))))
+#define	ADDSARG() do { \
+	if (flags&MAXINT) \
+		ADDTYPE(T_MAXINT); \
+	else if (flags&PTRINT) \
+		ADDTYPE(T_PTRINT); \
+	else if (flags&SIZEINT) \
+		ADDTYPE(T_SSIZEINT); \
+	else if (flags&LLONGINT) \
+		ADDTYPE(T_LLONG); \
+	else if (flags&LONGINT) \
+		ADDTYPE(T_LONG); \
+	else if (flags&SHORTINT) \
+		ADDTYPE(T_SHORT); \
+	else if (flags&CHARINT) \
+		ADDTYPE(T_CHAR); \
+	else \
+		ADDTYPE(T_INT); \
+} while (0)
 
-#define	ADDUARG() \
-        ((flags&MAXINT) ? ADDTYPE(T_MAXUINT) : \
-	    ((flags&PTRINT) ? ADDTYPE(T_PTRINT) : \
-	    ((flags&SIZEINT) ? ADDTYPE(T_SIZEINT) : \
-	    ((flags&LLONGINT) ? ADDTYPE(T_U_LLONG) : \
-	    ((flags&LONGINT) ? ADDTYPE(T_U_LONG) : \
-	    ((flags&SHORTINT) ? ADDTYPE(T_U_SHORT) : \
-	    ((flags&CHARINT) ? ADDTYPE(T_U_CHAR) : ADDTYPE(T_U_INT))))))))
+#define	ADDUARG() do { \
+	if (flags&MAXINT) \
+		ADDTYPE(T_MAXUINT); \
+	else if (flags&PTRINT) \
+		ADDTYPE(T_PTRINT); \
+	else if (flags&SIZEINT) \
+		ADDTYPE(T_SIZEINT); \
+	else if (flags&LLONGINT) \
+		ADDTYPE(T_U_LLONG); \
+	else if (flags&LONGINT) \
+		ADDTYPE(T_U_LONG); \
+	else if (flags&SHORTINT) \
+		ADDTYPE(T_U_SHORT); \
+	else if (flags&CHARINT) \
+		ADDTYPE(T_U_CHAR); \
+	else \
+		ADDTYPE(T_U_INT); \
+} while (0)
 
 	/*
 	 * Add * arguments to the type array.
@@ -1470,7 +1496,7 @@ overflow:
 
 finish:
 	if (typetable != NULL && typetable != stattypetable) {
-		munmap(typetable, *argtablesiz);
+		munmap(typetable, tablesize);
 		typetable = NULL;
 	}
 	return (ret);
@@ -1483,16 +1509,23 @@ static int
 __grow_type_table(unsigned char **typetable, int *tablesize)
 {
 	unsigned char *oldtable = *typetable;
-	int newsize = *tablesize * 2;
+	int newsize;
+
+	if (*tablesize > INT_MAX / 2) {
+		errno = EOVERFLOW;
+		return (-1);
+	}
+	newsize = *tablesize * 2;
 
 	if (newsize < getpagesize())
 		newsize = getpagesize();
 
 	if (*tablesize == STATIC_ARG_TBL_SIZE) {
-		*typetable = mmap(NULL, newsize, PROT_WRITE|PROT_READ,
+		unsigned char *new = mmap(NULL, newsize, PROT_WRITE|PROT_READ,
 		    MAP_ANON|MAP_PRIVATE, -1, 0);
-		if (*typetable == MAP_FAILED)
+		if (new == MAP_FAILED)
 			return (-1);
+		*typetable = new;
 		bcopy(oldtable, *typetable, *tablesize);
 	} else {
 		unsigned char *new = mmap(NULL, newsize, PROT_WRITE|PROT_READ,
```