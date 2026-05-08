# Decoded Database Path Overflows Stack Buffer

## Classification

Memory corruption, high severity.

## Affected Locations

`usr.bin/locate/locate/fastfind.c:201`

## Summary

`fastfind_mmap()` decodes attacker-controlled locate database entries into a stack buffer `path[PATH_MAX]`. The code validates only the starting overlay offset with `sane_count(count)` before setting `p = path + count`, but it does not validate the total decoded entry length before appending literal bytes or bigram expansions.

A crafted database entry can therefore decode to more than `PATH_MAX` bytes and write past the end of `path`, corrupting the stack of the victim `locate` process.

## Provenance

Verified from the provided source, reproduced with an ASan harness, and patched according to the supplied diff.

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Victim runs `locate` against an attacker-controlled locate database.

## Proof

The vulnerable function declares a fixed stack buffer:

```c
u_char bigram1[NBG], bigram2[NBG], path[PATH_MAX];
```

The main loop updates `count`, validates it, and overlays the previous decoded path:

```c
sane_count(count);
p = path + count;
```

This check confirms only that `count` is a sane starting offset. It does not ensure that subsequent decoded bytes fit in `path`.

The decoder then appends attacker-controlled content:

```c
*p++ = c;
```

for literal bytes, and:

```c
*p++ = bigram1[c];
*p++ = bigram2[c];
```

for bigram bytes.

The reproduced input used:

- A valid `2*NBG` byte bigram header.
- An initial delta byte of `OFFSET`, making `count == 0`.
- More than `PATH_MAX` literal printable `B` bytes.

ASan confirmed `AddressSanitizer: stack-buffer-overflow` at `usr.bin/locate/locate/fastfind.c:200`, with the write immediately past the `path` stack object.

## Why This Is A Real Bug

The database file is attacker-controlled under the stated precondition, and every decoded byte advances `p` without a capacity check. Because `path` is a fixed-size stack object, any decoded entry longer than `PATH_MAX` causes an out-of-bounds stack write before later null termination or matching logic can run.

This is not a theoretical parser inconsistency: the reproducer triggers an ASan-confirmed stack-buffer-overflow in the committed source.

## Fix Requirement

Reject decoded entries whose starting overlay offset or appended decoded bytes would exceed `PATH_MAX`.

The check must happen before each write into `path`, including both single-byte literal writes and two-byte bigram expansions.

## Patch Rationale

The patch adds capacity validation immediately before each append:

```diff
+				sane_count(p - path + 1);
 				*p++ = c;
```

and before bigram expansion:

```diff
+				sane_count(p - path + 2);
 				*p++ = bigram1[c];
 				*p++ = bigram2[c];
```

This preserves existing decoding behavior for valid databases while rejecting entries that would advance `p` beyond the valid `path` capacity. The bigram case checks for both pending writes as a unit, preventing a partial in-bounds write followed by an out-of-bounds write.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/locate/locate/fastfind.c b/usr.bin/locate/locate/fastfind.c
index aec9078..778dddc 100644
--- a/usr.bin/locate/locate/fastfind.c
+++ b/usr.bin/locate/locate/fastfind.c
@@ -197,6 +197,7 @@ fastfind_mmap
 				if (c == cc)
 #endif /* FF_ICASE */
 					foundchar = p;
+				sane_count(p - path + 1);
 				*p++ = c;
 			} else {
 				/* bigrams are parity-marked */
@@ -210,6 +211,7 @@ fastfind_mmap
 #endif /* FF_ICASE */
 					foundchar = p + 1;
 
+				sane_count(p - path + 2);
 				*p++ = bigram1[c];
 				*p++ = bigram2[c];
 			}
```