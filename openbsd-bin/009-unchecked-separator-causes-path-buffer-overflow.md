# unchecked separator causes path buffer overflow

## Classification

Out-of-bounds write, medium severity.

## Affected Locations

`make/targequiv.c:223`

## Summary

`parse_reduce()` grows its shared heap path buffer before copying path component bytes, but did not ensure capacity before copying a following `/` separator or the final NUL terminator. An attacker-controlled make target with a path component of length `PATH_MAX - 2` followed by `/` can cause a one-byte heap overwrite past the allocated reduction buffer during alias resolution.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `make` parses attacker-controlled target names.
- Target alias lookup is reached through `look_harder_for_target()`.
- The crafted target name participates in sibling/name matching.
- The path contains a component of length `PATH_MAX - 2` followed by a trailing slash.

## Proof

Target names are stored in `GNode->name` and compared during alias resolution:

- `look_harder_for_target()` calls `find_siblings()`.
- `find_siblings()` calls `names_match()`.
- `names_match()` calls `absolute_reduce()` for absolute target names.
- `absolute_reduce()` initializes the shared heap buffer with size `PATH_MAX` and starts reduction with `i == 1`.
- `parse_reduce()` grows the buffer only while copying component bytes.
- With input `"/" + (PATH_MAX - 2) * "A" + "/"`, component copying ends with `i == PATH_MAX - 1`.
- The unchecked separator write stores `/` at `buffer[PATH_MAX - 1]`.
- The unchecked terminator write then stores NUL at `buffer[PATH_MAX]`, one byte past the heap allocation.

A small ASan harness using the committed `parse_reduce()` logic and the crafted input reports a heap-buffer-overflow on the final terminator write.

## Why This Is A Real Bug

The overflow is reachable from attacker-controlled Makefile target names before recipes execute. The write is outside the heap allocation owned by the shared reduction buffer, producing memory corruption with practical denial-of-service potential and possible exploitation depending on allocator layout.

## Fix Requirement

Ensure `parse_reduce()` checks and grows the buffer before every write site, including:

- component byte writes
- separator `/` writes
- final NUL terminator writes

## Patch Rationale

The patch adds the missing capacity checks immediately before writing a separator and before writing the final terminator. It preserves existing buffer-growth behavior and uses the same `bufsize *= 2` plus `erealloc()` pattern already used for component bytes.

This directly closes the overflow condition:

- If `i == bufsize - 1` before writing `/`, the buffer is enlarged first.
- If `i == bufsize` before writing NUL, the buffer is enlarged first.

## Residual Risk

None

## Patch

```diff
diff --git a/make/targequiv.c b/make/targequiv.c
index 48ba4bc..d0bc4da 100644
--- a/make/targequiv.c
+++ b/make/targequiv.c
@@ -220,8 +220,17 @@ parse_reduce(size_t i, const char *src)
 			}
 			buffer[i++] = *src++;
 		}
-		if (src[0] == '/') 
+		if (src[0] == '/') {
+			if (i > bufsize - 2) {
+				bufsize *= 2;
+				buffer = erealloc(buffer, bufsize);
+			}
 			buffer[i++] = *src++;
+		}
+	}
+	if (i > bufsize - 1) {
+		bufsize *= 2;
+		buffer = erealloc(buffer, bufsize);
 	}
 	buffer[i++] = 0;
 	return i;
```