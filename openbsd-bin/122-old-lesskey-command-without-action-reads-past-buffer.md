# Old Lesskey Command Without Action Reads Past Buffer

## Classification

Out-of-bounds read, medium severity.

## Affected Locations

`usr.bin/less/decode.c:284`

## Summary

An attacker-controlled old-format `LESSKEY` file can define a command that ends at its terminating NUL byte without the required action byte. The old lesskey parser accepted this malformed table, after which command-table processing read one byte past the heap buffer to fetch the missing action.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Secure mode is off.

`LESSKEY` points to an attacker-controlled file.

The attacker file is parsed as an old-format lesskey file.

## Proof

A minimal malformed old-format lesskey table such as `ab\0` is sufficient:

- `lesskey()` reads the attacker-controlled file into a heap buffer of exactly `len` bytes.
- Because the file lacks new-format magic, `lesskey()` calls `old_lesskey(buf, len)`.
- The previous `old_lesskey()` check accepted files whose last or second-to-last byte was NUL.
- For `ab\0`, the command terminator is the final byte, so no action byte exists.
- `add_fcmd_table()` calls `add_cmd_table()`, which calls `expand_special_keys()`.
- `expand_special_keys()` scans to the final NUL, advances to `buf + len`, then executes `a = *fm++ & 0377`, reading one byte past the heap allocation.
- If startup processing does not trap, the linked table has `t_end = buf + len`.
- Later, typing `ab` reaches `cmd_search()`, where `a = *++p & 0377` reads the same missing action byte past `t_end`.

The reproducer confirmed this with a minimal ASan harness using the committed `expand_special_keys()` logic and a three-byte `ab\0` buffer. ASan reported a heap-buffer-overflow at the action-byte read.

## Why This Is A Real Bug

The command table format requires every command descriptor to contain:

`<command-bytes><NUL><action>`

The vulnerable parser only checked that the old-style file ended with a NUL in one of the final two positions. That permits a descriptor ending exactly at `<command-bytes><NUL>`, with no action byte.

Both `expand_special_keys()` and `cmd_search()` assume the action byte exists and dereference it unconditionally. With a heap buffer sized exactly to the lesskey file length, that dereference is outside the allocation.

The impact is a memory-safety failure from attacker-controlled input. Hardened or checked builds can abort; unchecked builds can consume adjacent heap data as the command action or extra marker.

## Fix Requirement

Reject old-format lesskey command tables unless every command terminator is followed by an action byte.

If an action byte has `A_EXTRA` set, also require the extra string to be NUL-terminated within the buffer.

## Patch Rationale

The patch replaces the insufficient final-byte heuristic in `old_lesskey()` with full table validation before the buffer is registered as a command table.

The new parser walks from `buf` to `buf + len` and validates each command descriptor:

- Finds the command’s terminating NUL within bounds.
- Requires one byte after the NUL for the action.
- Reads the action only after confirming it is in bounds.
- If `A_EXTRA` is set, requires the extra string’s terminating NUL within bounds.
- Rejects malformed tables before `add_fcmd_table()` can call `expand_special_keys()`.

This prevents both the startup-time overread in `expand_special_keys()` and the later command-match overread in `cmd_search()`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/less/decode.c b/usr.bin/less/decode.c
index 4846e0c..0498f0c 100644
--- a/usr.bin/less/decode.c
+++ b/usr.bin/less/decode.c
@@ -543,15 +543,33 @@ gint(char **sp)
 static int
 old_lesskey(char *buf, int len)
 {
+	char *p;
+	char *end;
+	int a;
+
 	/*
 	 * Old-style lesskey file.
-	 * The file must end with either
-	 *	..,cmd,0,action
-	 * or	...,cmd,0,action|A_EXTRA,string,0
-	 * So the last byte or the second to last byte must be zero.
+	 * Each command must have an action byte after its terminating null.
+	 * If the action has A_EXTRA, it must also have a terminating null.
 	 */
-	if (buf[len-1] != '\0' && buf[len-2] != '\0')
-		return (-1);
+	end = buf + len;
+	for (p = buf; p < end; ) {
+		while (p < end && *p != '\0')
+			p++;
+		if (p == end)
+			return (-1);
+		p++;
+		if (p == end)
+			return (-1);
+		a = *p++ & 0377;
+		if (a & A_EXTRA) {
+			while (p < end && *p != '\0')
+				p++;
+			if (p == end)
+				return (-1);
+			p++;
+		}
+	}
 	add_fcmd_table(buf, len);
 	return (0);
 }
```