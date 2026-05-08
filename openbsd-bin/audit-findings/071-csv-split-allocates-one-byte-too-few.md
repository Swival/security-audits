# CSV split allocates one byte too few

## Classification

High severity out-of-bounds write.

Confidence: certain.

## Affected Locations

`usr.bin/awk/run.c:1344`

`usr.bin/awk/run.c:1752`

## Summary

When `awk` runs `split(s, a)` with CSV mode enabled and no explicit separator, the CSV split path allocates a reusable field buffer with `malloc(strlen(s))`. For an unquoted field that spans the remaining input, the parser copies all `strlen(s)` bytes and then appends a terminating NUL, writing one byte past the heap allocation.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

The issue was reproduced on the normal CSV `split` execution path and confirmed with ASan as a heap-buffer-overflow at the byte immediately after the allocated region.

## Preconditions

`awk` runs `split(s, a)` with CSV enabled on attacker-controlled nonempty `s`.

A practical trigger is an awk program such as:

```sh
awk --csv '{ split($0, a) }'
```

with attacker-controlled CSV input such as:

```text
abc
```

## Proof

In the CSV branch of `split()`:

```c
char *newt = (char *) malloc(strlen(s));
```

For input `abc`, `strlen(s)` is 3, so the allocation is 3 bytes.

The unquoted-field loop then copies all non-comma bytes:

```c
while (*s != ',' && *s != '\0')
	*fr++ = *s++;
*fr++ = 0;
```

For `abc`, the loop writes `a`, `b`, and `c` into the 3-byte allocation. The following terminator write stores `0` one byte past the allocation.

The buffer is then consumed by `is_number()` and `setsymtab()`, so the overflow occurs before the split field is stored.

## Why This Is A Real Bug

The path is reachable through documented CSV behavior when `CSV` is true and no explicit split separator is supplied.

The input only needs to be a nonempty unquoted field with no comma, such as `abc`.

The write is a heap out-of-bounds write by one byte, which can corrupt allocator metadata or adjacent heap data and can cause attacker-triggered process memory corruption or denial of service.

ASan confirmed the behavior as `malloc(3)` followed by a heap-buffer-overflow on the terminator write immediately after the 3-byte region.

## Fix Requirement

Allocate space for the copied field plus the terminating NUL.

Check the allocation result and fail safely if memory cannot be allocated.

## Patch Rationale

Changing the allocation from `strlen(s)` to `strlen(s) + 1` makes the reusable field buffer large enough for the longest possible decoded CSV field plus its NUL terminator.

Adding a `NULL` check matches nearby allocation failure handling in `split()` and avoids dereferencing `newt` after allocation failure.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/awk/run.c b/usr.bin/awk/run.c
index 10ec45b..9ddddee 100644
--- a/usr.bin/awk/run.c
+++ b/usr.bin/awk/run.c
@@ -1749,7 +1749,9 @@ Cell *split(Node **a, int nnn)	/* split(a[0], a[1], a[2]); a[3] is type */
 		pfa = NULL;
 
 	} else if (a[2] == NULL && CSV) {	/* CSV only if no explicit separator */
-		char *newt = (char *) malloc(strlen(s)); /* for building new string; reuse for each field */
+		char *newt = (char *) malloc(strlen(s) + 1); /* for building new string; reuse for each field */
+		if (newt == NULL)
+			FATAL("out of space in split");
 		for (;;) {
 			char *fr = newt;
 			n++;
```