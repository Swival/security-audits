# Oversized Positional Index Writes Past Type Table

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`stdio/vfwprintf.c:946`

Primary vulnerable operation reproduced in `__find_arguments`:

- `stdio/vfwprintf.c:1147`
- `stdio/vfwprintf.c:1151`
- `stdio/vfwprintf.c:1239`
- `stdio/vfwprintf.c:1467`

## Summary

An attacker-controlled wide printf format containing a very large positional argument index, such as `L"%1000000$d"`, can make `__find_arguments` write past the allocated positional argument type table.

The vulnerable `ADDTYPE` macro grows `typetable` only once when `nextarg >= tablesize`, then writes `typetable[nextarg++] = type` unconditionally. Because `__grow_type_table` only doubles the table size, with a page-size minimum, a sufficiently large `N$` index remains outside the resized table.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced and patched.

## Preconditions

- The application passes attacker-controlled wide format strings to `vfwprintf`.
- The attacker can include a positional format specifier with a large numeric index, for example `N$`.

## Proof

Control flow:

- `__vfwprintf` parses a positional specifier and invokes `__find_arguments` when `argtable == NULL`.
- `__find_arguments` parses the same `N$` positional index and assigns `nextarg = n`.
- The conversion later reaches `ADDTYPE`.
- The original `ADDTYPE` performs at most one call to `__grow_type_table`.
- `__grow_type_table` only doubles the table size, or raises it to page size.
- `ADDTYPE` then writes `typetable[nextarg++] = type` even when `nextarg` is still far beyond `tablesize`.

Reproduced behavior:

- A reduced harness using `L"%1000000$d"` grew the table once to page size.
- It then attempted to write `typetable[1000000]`.
- The process crashed with `SIGBUS`.

## Why This Is A Real Bug

The positional index is attacker-controlled format data and directly determines the write index into `typetable`.

The table growth logic does not ensure the target index is within bounds before writing. A single expansion from the static table to page size is insufficient for large indexes such as `1000000`.

The failing write is an attacker-indexed out-of-bounds byte write from an mmap-backed table. In practice this can crash the process for denial of service, and it can corrupt adjacent mapped memory if the target offset lands in mapped memory.

## Fix Requirement

`ADDTYPE` must ensure `nextarg < tablesize` before writing to `typetable`.

The fix must:

- Grow the type table in a loop until the requested index fits.
- Detect and propagate `__grow_type_table` failure.
- Avoid integer overflow while calculating larger table sizes.
- Unmap the type table using the actual type-table allocation size.

## Patch Rationale

The patch changes `ADDTYPE` from a single-growth expression macro into a statement macro that loops while `nextarg >= tablesize`.

If `__grow_type_table` fails, `ADDTYPE` sets `ret = -1` and exits through `finish`, preventing the out-of-bounds write.

Because `ADDTYPE` can now branch with `goto`, `ADDSARG` and `ADDUARG` are converted from nested conditional expressions into statement macros. This preserves behavior while making failure propagation safe and explicit.

The patch also fixes cleanup by unmapping `typetable` with `tablesize`, not `*argtablesiz`, because `typetable` has its own allocation size independent from the later argument table allocation.

Finally, `__grow_type_table` now rejects doubling when `*tablesize > INT_MAX / 2`, sets `errno = EOVERFLOW`, and returns failure. This prevents signed integer overflow during table growth.

## Residual Risk

None

## Patch

```diff
diff --git a/stdio/vfwprintf.c b/stdio/vfwprintf.c
index 963c475..789130f 100644
--- a/stdio/vfwprintf.c
+++ b/stdio/vfwprintf.c
@@ -1144,29 +1144,55 @@ __find_arguments(const wchar_t *fmt0, va_list ap, union arg **argtable,
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
@@ -1451,7 +1477,7 @@ overflow:
 
 finish:
 	if (typetable != NULL && typetable != stattypetable) {
-		munmap(typetable, *argtablesiz);
+		munmap(typetable, tablesize);
 		typetable = NULL;
 	}
 	return (ret);
@@ -1464,16 +1490,22 @@ static int
 __grow_type_table(unsigned char **typetable, int *tablesize)
 {
 	unsigned char *oldtable = *typetable;
-	int newsize = *tablesize * 2;
+	int newsize;
 
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