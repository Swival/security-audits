# PATH_MAX .so name overflows fname

## Classification

Out-of-bounds write, medium severity.

## Affected Locations

`usr.bin/deroff/deroff.c:428`

## Summary

`deroff` copies `.so` filenames into the global buffer `fname[PATH_MAX]` without reserving space for the trailing NUL byte. A `.so` argument containing exactly `PATH_MAX` non-delimiter bytes advances the write pointer to one byte past `fname`, after which `*p = '\0'` performs a one-byte global out-of-bounds write.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`deroff` processes attacker-controlled troff input without `-i`.

## Proof

`iflag` defaults to `NO`; only `-i` disables `.so` processing in `so()`.

`.so` is registered in `troffmactab` and dispatched by `comline()` through `(*(mp->func))(c12)`. When the matched macro is `.so`, `so()` calls `getfname()` before attempting to open the referenced file, so the overflow occurs during parsing even if the later `fopen()` fails.

In `getfname()`:

```c
for (p = fname ; p - fname < sizeof(fname) && (*p = c) != '\n' &&
    c != ' ' && c != '\t' && c != '\\'; ++p)
	C;
*p = '\0';
```

With `.so ` followed by `PATH_MAX` bytes that are not newline, space, tab, or backslash, the loop stores the last byte at `fname[PATH_MAX - 1]`, increments `p` to `fname + PATH_MAX`, exits because `p - fname < sizeof(fname)` is false, then writes `'\0'` one byte past the global buffer.

## Why This Is A Real Bug

The destination object is `char fname[PATH_MAX]`, so valid indexes are `0` through `PATH_MAX - 1`. The loop permits all `PATH_MAX` slots to be filled with non-delimiter data, then unconditionally writes the terminator at index `PATH_MAX`. The write is attacker-triggerable through a normal `.so` macro line and does not require the named file to exist.

## Fix Requirement

Reserve one byte in `fname` for the NUL terminator by limiting copied filename bytes to `sizeof(fname) - 1`.

## Patch Rationale

Changing the loop bound from `sizeof(fname)` to `sizeof(fname) - 1` preserves existing parsing behavior for shorter names while guaranteeing that the unconditional `*p = '\0'` remains within `fname`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/deroff/deroff.c b/usr.bin/deroff/deroff.c
index 2486fb4..e93657b 100644
--- a/usr.bin/deroff/deroff.c
+++ b/usr.bin/deroff/deroff.c
@@ -425,7 +425,7 @@ getfname(void)
 	while (C == ' ')
 		;	/* nothing */
 
-	for (p = fname ; p - fname < sizeof(fname) && (*p = c) != '\n' &&
+	for (p = fname ; p - fname < sizeof(fname) - 1 && (*p = c) != '\n' &&
 	    c != ' ' && c != '\t' && c != '\\'; ++p)
 		C;
 	*p = '\0';
```