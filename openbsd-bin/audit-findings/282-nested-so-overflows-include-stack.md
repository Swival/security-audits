# nested .so overflows include stack

## Classification

Out-of-bounds write. Severity: medium. Confidence: certain.

## Affected Locations

`usr.bin/deroff/deroff.c:1173`

## Summary

`deroff` tracks nested `.so` includes in `files[MAXFILES]`, but the nesting-depth check accepts the one-past array position. A twentieth nested unique `.so` include advances `filesp` to `&files[20]` while `files` only has valid indices `0..19`, then writes a `FILE *` through that one-past pointer.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`deroff` processes attacker-controlled troff input with `.so` includes enabled, which is the default behavior unless `-i` is used.

## Proof

`files` is declared as `FILE *files[MAXFILES]` with `MAXFILES == 20`, so valid entries are `files[0]` through `files[19]`.

`main()` stores the initial input in `files[0]` and initializes `filesp` to `&files[0]`.

When a `.so` directive is processed, `so()` calls `getfname()`, pre-increments `filesp`, checks the resulting distance, and then writes the newly opened file into the stack:

```c
if (++filesp - &files[0] > MAXFILES)
	err(1, "too many nested files (max %d)", MAXFILES);
infile = *filesp = opn(fname);
```

On the twentieth nested unique `.so`, `filesp` advances from `&files[19]` to `&files[20]`. The pointer distance is exactly `20`, so `> MAXFILES` is false. Execution then reaches `*filesp = opn(fname)`, writing one `FILE *` past the end of `files`.

`getfname()` only suppresses duplicate include names, so a chain of distinct existing files `f0 -> f1 -> ... -> f20` reaches the bad write. A local ASan build with compatibility shims crashed after this chain, consistent with include-stack corruption and denial of service from attacker-controlled input.

## Why This Is A Real Bug

The check is an off-by-one bound check on a fixed-size array. `files[MAXFILES]` cannot legally store an element at offset `MAXFILES`; the maximum valid offset is `MAXFILES - 1`. Because `files[0]` is already occupied by the current input, the twentieth nested include causes a write through the one-past pointer before any error is raised.

## Fix Requirement

Reject the include before writing when the incremented `filesp` distance is greater than or equal to `MAXFILES`.

## Patch Rationale

Changing the check from `> MAXFILES` to `>= MAXFILES` rejects `&files[20]`, the first invalid position, while preserving the existing limit and behavior for valid stack entries `files[0]` through `files[19]`.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/deroff/deroff.c b/usr.bin/deroff/deroff.c
index 2486fb4..b46325a 100644
--- a/usr.bin/deroff/deroff.c
+++ b/usr.bin/deroff/deroff.c
@@ -1170,7 +1170,7 @@ so(void)
 	if (!iflag) {
 		getfname();
 		if (fname[0]) {
-			if (++filesp - &files[0] > MAXFILES)
+			if (++filesp - &files[0] >= MAXFILES)
 				err(1, "too many nested files (max %d)",
 				    MAXFILES);
 			infile = *filesp = opn(fname);
```