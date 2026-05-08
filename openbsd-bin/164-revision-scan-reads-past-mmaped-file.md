# revision scan reads past mmaped file

## Classification

Out-of-bounds read; medium severity; denial of service.

## Affected Locations

`usr.bin/patch/inp.c:413`

## Summary

`plan_a()` maps a regular target file into `i_womp` with length `i_size`, but the revision check passed that mapping to `rev_in_string()` as if it were a NUL-terminated C string. `rev_in_string()` scanned with `for (s = string; *s; s++)`, so a mapped file containing no NUL byte could be read past `i_size`. A page-aligned target file can make the next byte unmapped and crash `patch`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `revision` is non-NULL.
- `plan_a()` is used for a regular target file.
- The mapped target file has no NUL byte before the end of the mapping.
- A malicious patch/input supplier can influence the target file contents and cause a revision check, for example via `Prereq:`.

## Proof

`plan_a()` maps the file:

```c
i_womp = mmap(NULL, i_size, PROT_READ, MAP_PRIVATE, ifd, 0);
```

It then scans the mapping with an explicit bound only while building line pointers:

```c
for (s = i_womp, i = 0; i < i_size && *s != '\0'; s++, i++) {
```

The revision check previously called:

```c
rev_in_string(i_womp)
```

The vulnerable function treated the mapping as NUL-terminated:

```c
for (s = string; *s; s++) {
```

The reproduced ASan harness used a page-sized regular file filled with `A` bytes and `revision = "REV"`. The Plan A path crashed in the unbounded scan:

```text
ERROR: AddressSanitizer: SEGV
#0 rev_in_string inp.c:423
#1 plan_a inp.c:250
#2 scan_input inp.c:98
```

## Why This Is A Real Bug

The memory returned by `mmap()` is valid only for `i_size` bytes. `plan_a()` does not append a NUL terminator to `i_womp`, and comments elsewhere explicitly note that Plan A line pointers are not NUL-terminated. Therefore `rev_in_string()` cannot safely use C-string traversal on `i_womp`. If the target file has no NUL byte, `*s` reads byte `i_size` and beyond, outside the mapping.

The crash is attacker-triggerable under the stated preconditions and produces a practical denial of service.

## Fix Requirement

Pass the mapped buffer length into `rev_in_string()` and ensure every comparison and whitespace check is bounded by that length. Preserve Plan B behavior by passing the actual line length for NUL-terminated line buffers.

## Patch Rationale

The patch changes `rev_in_string()` from a C-string scanner to a length-bounded scanner:

- Updates the prototype to `rev_in_string(const char *, size_t)`.
- Calls `rev_in_string(i_womp, (size_t)i_size)` from `plan_a()`.
- Calls `rev_in_string(p, len)` from `plan_b()`.
- Checks the beginning-of-buffer match only when `patlen < len`.
- Stops early when `len == 0` or the pattern cannot fit with required surrounding whitespace.
- Iterates with an index bounded by `len - patlen - 1`.
- Preserves the existing behavior of stopping at embedded NUL bytes during scanning.

This removes the out-of-bounds read because all accesses to `string[patlen]`, `string[i]`, `string + i + 1`, and `string[i + patlen + 1]` are guarded by `len`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/patch/inp.c b/usr.bin/patch/inp.c
index 3583814..7dcc94a 100644
--- a/usr.bin/patch/inp.c
+++ b/usr.bin/patch/inp.c
@@ -57,7 +57,7 @@ static size_t	lines_per_buf;	/* how many lines per buffer */
 static size_t	tibuflen;	/* plan b buffer length */
 static size_t	tireclen;	/* length of records in tmp file */
 
-static bool	rev_in_string(const char *);
+static bool	rev_in_string(const char *, size_t);
 static bool	reallocate_lines(size_t *);
 
 /* returns false if insufficient memory */
@@ -247,7 +247,7 @@ plan_a(const char *filename)
 	/* now check for revision, if any */
 
 	if (revision != NULL) {
-		if (i_womp == NULL || !rev_in_string(i_womp)) {
+		if (i_womp == NULL || !rev_in_string(i_womp, (size_t)i_size)) {
 			if (force) {
 				if (verbose)
 					say("Warning: this file doesn't appear "
@@ -301,7 +301,7 @@ plan_b(const char *filename)
 			last_line_missing_eol = true;
 			len++;
 		}
-		if (revision != NULL && !found_revision && rev_in_string(p))
+		if (revision != NULL && !found_revision && rev_in_string(p, len))
 			found_revision = true;
 		if (len > maxlen)
 			maxlen = len;	/* find longest line */
@@ -409,20 +409,22 @@ ifetch(LINENUM line, int whichbuf)
  * True if the string argument contains the revision number we want.
  */
 static bool
-rev_in_string(const char *string)
+rev_in_string(const char *string, size_t len)
 {
-	const char	*s;
-	size_t		patlen;
+	size_t		i, patlen;
 
 	if (revision == NULL)
 		return true;
 	patlen = strlen(revision);
-	if (strnEQ(string, revision, patlen) &&
+	if (patlen < len && strnEQ(string, revision, patlen) &&
 	    isspace((unsigned char)string[patlen]))
 		return true;
-	for (s = string; *s; s++) {
-		if (isspace((unsigned char)*s) && strnEQ(s + 1, revision, patlen) &&
-		    isspace((unsigned char)s[patlen + 1])) {
+	if (len == 0 || patlen >= len - 1)
+		return false;
+	for (i = 0; i < len - patlen - 1 && string[i] != '\0'; i++) {
+		if (isspace((unsigned char)string[i]) &&
+		    strnEQ(string + i + 1, revision, patlen) &&
+		    isspace((unsigned char)string[i + patlen + 1])) {
 			return true;
 		}
 	}
```