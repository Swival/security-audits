# Unterminated A_EXTRA string reads beyond lesskey buffer

## Classification

Out-of-bounds read, medium severity. Confidence: certain.

## Affected Locations

`usr.bin/less/decode.c:286`

## Summary

`less` accepts command sections from a user-controlled `LESSKEY` file and passes each section buffer and length into `expand_special_keys()`. When an action byte has `A_EXTRA` set, `expand_special_keys()` scans the following extra string with `while (*fm++ != '\0')` without checking the section boundary. A malformed section that ends after an `A_EXTRA` action byte causes reads beyond the section and can continue past the heap allocation containing the lesskey file.

## Provenance

Verified from the provided source, reproducer, and patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `less` is not running in secure mode.
- `less` loads an attacker-controlled `LESSKEY` file.
- The lesskey file contains a command, edit, or variable section with an `A_EXTRA` action lacking a NUL-terminated extra string within that section.

## Proof

The vulnerable flow is:

1. `lesskey()` reads the attacker-selected lesskey file into a heap buffer.
2. `new_lesskey()` validates the section length only as `p + n < end`, then passes `p, n` to `add_fcmd_table()`, `add_ecmd_table()`, or `add_var_table()`.
3. `add_cmd_table()` calls `expand_special_keys(buf, len)`.
4. In `expand_special_keys()`, after command-string processing, `a = *fm++ & 0377` consumes the action byte.
5. If `a & A_EXTRA`, the old code executes `while (*fm++ != '\0') continue;` without checking `fm < table + len`.

The reproduced malformed file shape was:

```text
\0M+G, c, length 3,0, section bytes 'a',0,A_F_SEARCH|A_EXTRA, followed by xEnd
```

At runtime, the action byte is the final in-section byte. Reading the extra string starts with `fm == table + len`, so the scan reads `xEnd` outside the section and then past the allocated lesskey buffer. An ASan harness reported `heap-buffer-overflow` in `expand_special_keys`, reading 0 bytes after the 14-byte lesskey allocation.

## Why This Is A Real Bug

The parser receives an explicit section length but the `A_EXTRA` scan ignores it. Existing controls do not prevent the stated case: secure mode skips lesskey loading, and `more` mode returns before user lesskey loading, but normal non-secure `less` still loads attacker-controlled `LESSKEY`. The ASan reproduction confirms the unchecked scan reaches heap memory beyond the lesskey allocation.

## Fix Requirement

Bound the `A_EXTRA` extra-string scan by the command table section end and reject a section if the terminating NUL is not present before `table + len`.

## Patch Rationale

The patch changes `expand_special_keys()` from `void` to `int`, computes `end = table + len`, and scans extras only while `fm < end`. If the scan reaches `end` before finding `'\0'`, it returns `-1`. `add_cmd_table()` now treats that failure like an allocation/parser failure, frees the newly allocated table node, and rejects the malformed table instead of linking it.

This preserves valid tables because properly terminated `A_EXTRA` strings still advance past the NUL and parsing continues unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/less/decode.c b/usr.bin/less/decode.c
index 4846e0c..c6590d7 100644
--- a/usr.bin/less/decode.c
+++ b/usr.bin/less/decode.c
@@ -233,16 +233,18 @@ static struct tablelist *list_sysvar_tables = NULL;
 /*
  * Expand special key abbreviations in a command table.
  */
-static void
+static int
 expand_special_keys(char *table, int len)
 {
 	char *fm;
 	char *to;
+	char *end;
 	int a;
 	char *repl;
 	int klen;
 
-	for (fm = table; fm < table + len; ) {
+	end = table + len;
+	for (fm = table; fm < end; ) {
 		/*
 		 * Rewrite each command in the table with any
 		 * special key abbreviations expanded.
@@ -279,10 +281,14 @@ expand_special_keys(char *table, int len)
 		fm++;
 		a = *fm++ & 0377;
 		if (a & A_EXTRA) {
-			while (*fm++ != '\0')
-				continue;
+			while (fm < end && *fm != '\0')
+				fm++;
+			if (fm >= end)
+				return (-1);
+			fm++;
 		}
 	}
+	return (0);
 }
 
 /*
@@ -330,7 +336,10 @@ add_cmd_table(struct tablelist **tlist, char *buf, int len)
 	if ((t = calloc(1, sizeof (struct tablelist))) == NULL) {
 		return (-1);
 	}
-	expand_special_keys(buf, len);
+	if (expand_special_keys(buf, len) < 0) {
+		free(t);
+		return (-1);
+	}
 	t->t_start = buf;
 	t->t_end = buf + len;
 	t->t_next = *tlist;
```