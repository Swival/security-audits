# blank banner line underreads output buffer

## Classification

Out-of-bounds read. Severity: medium. Confidence: certain.

## Affected Locations

`usr.sbin/lpd/lp_banner.c:1142`

## Summary

`lp_banner()` renders each banner row into the stack buffer `outbuf`, then trims trailing spaces with a predecrementing pointer expression that dereferences before validating the lower bound. If a rendered row contains only background spaces, the loop reads one byte before `outbuf`.

## Provenance

Verified from supplied source, reproducer evidence, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`lpd` prints attacker-controlled banner text.

## Proof

An attacker-controlled banner string containing a single space is sufficient.

The space glyph in `scnkey` is entirely background. During banner rendering, `lp_banner(fd, " ", 132)` fills the current row with spaces in `outbuf`. The trimming loop then executes:

```c
while (*--strp == BACKGND && strp >= outbuf)
	;
```

For an all-space row, `strp` walks down through every byte of `outbuf`. After reading `outbuf[0]` as `BACKGND`, the next iteration predecrements `strp` to `outbuf - 1` and dereferences it before `strp >= outbuf` is evaluated.

Runtime confirmation from the reproducer: compiling a tiny caller with ASan and invoking `lp_banner(fd, " ", 132)` aborts with `AddressSanitizer: stack-buffer-underflow` at `usr.sbin/lpd/lp_banner.c:1144`, with `outbuf` starting at stack offset 32 and the read at offset 31.

## Why This Is A Real Bug

The bounds check is ordered after the dereference in the `&&` expression. C evaluates the left operand first, so `*--strp` is performed before `strp >= outbuf`.

All-space rendered rows are reachable from attacker-supplied banner text because the space glyph contains only `BACKGND` bytes. Therefore, a remote lpd client submitting a print job can trigger a one-byte stack read before `outbuf` during banner generation.

No evidence shows the underread byte is disclosed in normal printer output, but the memory-safety violation is directly reproducible.

## Fix Requirement

Check that `strp` is still above `outbuf` before decrementing and dereferencing it.

## Patch Rationale

The patch changes the trimming loop from:

```c
while (*--strp == BACKGND && strp >= outbuf)
```

to:

```c
while (strp > outbuf && *--strp == BACKGND)
```

This preserves the intended trailing-space trimming behavior while ensuring the predecrement and dereference can only occur when `strp` points past at least one valid byte in `outbuf`.

For all-space rows, the loop stops when `strp == outbuf`; it never evaluates `*--strp` from that position, so it cannot read `outbuf - 1`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.sbin/lpd/lp_banner.c b/usr.sbin/lpd/lp_banner.c
index 6d363df..dcdaec4 100644
--- a/usr.sbin/lpd/lp_banner.c
+++ b/usr.sbin/lpd/lp_banner.c
@@ -1141,7 +1141,7 @@ lp_banner(int scfd, char *scsp, int pw)
 			*strp++ = BACKGND;
 			*strp++ = BACKGND;
 		}
-		while (*--strp == BACKGND && strp >= outbuf)
+		while (strp > outbuf && *--strp == BACKGND)
 			;
 		strp++;
 		*strp++ = '\n';
```