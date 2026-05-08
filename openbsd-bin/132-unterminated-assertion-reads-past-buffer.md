# Unterminated Assertion Reads Past Buffer

## Classification

Medium severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`lib/libkeynote/environment.c:879`

## Summary

`kn_read_asserts` accepts a length-delimited buffer, scans only `bufferlen` bytes, then uses `strdup(ptr)` for the final assertion. If the final assertion is not NUL-terminated, `strdup` reads past the caller-supplied buffer while searching for a terminator.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced with a page-boundary harness that placed a one-byte assertion at the end of a readable page followed by an unmapped page. Execution crashed inside `strlen`/`strdup`.

## Preconditions

- Caller passes a non-NUL-terminated buffer.
- The buffer contains a valid trailing assertion slice.
- The last assertion is not followed by a NUL byte.
- A remote peer can supply KeyNote assertion bundles to a service that feeds them to `kn_read_asserts`.

## Proof

`kn_read_asserts` is an exported, length-based API documented and declared at `lib/libkeynote/keynote.h:163` and `lib/libkeynote/keynote.3:492`.

The parsing loop bounds itself with `i < bufferlen`, so the scan is length-aware. However, if `valid` remains set after the loop, the final assertion starts at `ptr` and the old implementation called:

```c
buf[*numassertions] = strdup(ptr);
```

`strdup` computes the source length using NUL-terminated string semantics. It ignores `bufferlen`, so an unterminated final assertion causes `strlen` and the following copy to read beyond the provided assertion buffer.

A one-byte buffer containing `A` is sufficient to set `valid`, reach the final-assertion path, and trigger the unbounded `strdup` read.

## Why This Is A Real Bug

The API contract is length-based, not NUL-terminated-string-based. The implementation correctly honors `bufferlen` during the main scan, then violates that contract only for the final assertion by calling `strdup`.

The reproduced crash at a readable-page/unmapped-page boundary confirms that the read extends beyond the supplied buffer and can cause attacker-controlled denial of service in consumers that parse peer-supplied assertion bundles.

## Fix Requirement

The final assertion must be copied using only the slice length derived from `buffer` and `bufferlen`.

It must not call string functions that discover length by scanning for a NUL byte outside the supplied bounds.

## Patch Rationale

The patch replaces `strdup(ptr)` with explicit allocation and bounded copy:

```c
buf[*numassertions] = calloc((buffer + bufferlen) - ptr + 1, sizeof(char));
memcpy(buf[*numassertions], ptr, (buffer + bufferlen) - ptr);
```

This mirrors the earlier assertion-copy path used when assertions are separated by consecutive newlines. The allocated size includes one extra byte for NUL termination because `calloc` zero-initializes the buffer, while `memcpy` copies only bytes inside the original length-delimited input.

The fix preserves existing ownership, error handling, and `keynote_errno = ERROR_MEMORY` behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/environment.c b/lib/libkeynote/environment.c
index 8307ee4..f171b8f 100644
--- a/lib/libkeynote/environment.c
+++ b/lib/libkeynote/environment.c
@@ -878,14 +878,17 @@ kn_read_asserts(char *buffer, int bufferlen, int *numassertions)
      */
     if (valid)
     {
-	/* This one's easy, we can just use strdup() */
-	if ((buf[*numassertions] = strdup(ptr)) == NULL) {
+	buf[*numassertions] = calloc((buffer + bufferlen) - ptr + 1,
+	                              sizeof(char));
+	if (buf[*numassertions] == NULL) {
 	    for (flag = 0; flag < *numassertions; flag++)
 	      free(buf[flag]);
 	    free(buf);
 	    keynote_errno = ERROR_MEMORY;
 	    return NULL;
 	}
+
+	memcpy(buf[*numassertions], ptr, (buffer + bufferlen) - ptr);
 	(*numassertions)++;
     }
```
