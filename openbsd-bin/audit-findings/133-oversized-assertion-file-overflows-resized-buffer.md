# oversized assertion file overflows resized buffer

## Classification

Out-of-bounds write. Severity: high. Confidence: certain.

## Affected Locations

`lib/libkeynote/keynote-verify.c:273`

## Summary

The non-local assertion file path used `sb.st_size` from `fstat()` to resize an `int` buffer length, then used the original `off_t` file size for `read()` and `memset()`. On platforms where `off_t` exceeds `int`, an oversized attacker-supplied assertion file could truncate the allocation size while preserving the larger I/O size, causing heap writes past the allocated assertion buffer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A non-local assertion file is supplied as a positional argument.
- `off_t` is wider than `int`.
- The attacker-controlled `sb.st_size` exceeds the representable `int` allocation length.
- The truncated `calloc(cl, 1)` allocation succeeds.

## Proof

In the non-local assertion loop, `argv[argc]` is opened and `fstat(fd, &sb)` obtains the file size from an attacker-controlled file.

Before the patch:

```c
if (sb.st_size > cl - 1)
{
    free(buf);
    cl = sb.st_size + 1;
    buf = calloc(cl, sizeof(char));
    ...
}

i = read(fd, buf, sb.st_size);
...
memset(buf, 0, sb.st_size);
```

`cl` is an `int`, while `sb.st_size` is an `off_t`. If `sb.st_size + 1` truncates when assigned to `cl`, `calloc(cl, sizeof(char))` can allocate a smaller buffer than the original file size. The subsequent `read(fd, buf, sb.st_size)` writes using the full untruncated size, and `memset(buf, 0, sb.st_size)` can also write beyond the undersized allocation.

The reproducer confirmed reachability before assertion parsing or signature verification. Non-local assertions are documented as untrusted credentials in `lib/libkeynote/keynote.4:726` and `lib/libkeynote/keynote.4:729`.

## Why This Is A Real Bug

The size check, allocation, `read()`, and cleanup `memset()` occur before `kn_add_assertion()` and before signature verification. Therefore, the attacker does not need a syntactically valid assertion or valid signature to reach the heap write path.

The attacker controls the non-local assertion file size through the positional assertion argument. With an oversized file on a platform where `off_t` is wider than `int`, the allocation length can be truncated while the write length remains the original large `sb.st_size`. This creates a concrete heap out-of-bounds write condition with at least denial-of-service impact and possible memory corruption.

## Fix Requirement

Reject non-local assertion files whose `sb.st_size` is negative or cannot fit safely into the existing `int` allocation length plus trailing NUL byte requirement. Ensure the allocation size and subsequent `read()`/`memset()` lengths cannot diverge due to integer truncation.

## Patch Rationale

The patch adds `#include <limits.h>` and rejects non-local assertion files with:

```c
if (sb.st_size < 0 || sb.st_size > INT_MAX - 1)
{
    fprintf(stderr, "Assertion file <%s> too large.\n", argv[argc]);
    exit(1);
}
```

This check occurs immediately after `fstat()` and before assigning `sb.st_size + 1` into `cl`. Because `cl` is an `int`, bounding `sb.st_size` to `INT_MAX - 1` ensures `cl = sb.st_size + 1` cannot overflow or truncate. The allocated buffer length then remains consistent with the later `read(fd, buf, sb.st_size)` and `memset(buf, 0, sb.st_size)` calls.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/libkeynote/keynote-verify.c b/lib/libkeynote/keynote-verify.c
index 288d738..210c71b 100644
--- a/lib/libkeynote/keynote-verify.c
+++ b/lib/libkeynote/keynote-verify.c
@@ -25,6 +25,7 @@
 #include <ctype.h>
 #include <fcntl.h>
 #include <getopt.h>
+#include <limits.h>
 #include <regex.h>
 #include <stdio.h>
 #include <stdlib.h>
@@ -320,6 +321,12 @@ keynote_verify(int argc, char *argv[])
 	    exit(1);
 	}
 
+	if (sb.st_size < 0 || sb.st_size > INT_MAX - 1)
+	{
+	    fprintf(stderr, "Assertion file <%s> too large.\n", argv[argc]);
+	    exit(1);
+	}
+
 	if (sb.st_size > cl - 1)
 	{
 	    free(buf);
```