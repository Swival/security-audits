# Prefix Derivation Overflows Stack Buffer

## Classification

Memory corruption, medium severity.

## Affected Locations

`usr.bin/spell/spellprog.c:633`

## Summary

`trypref()` stores stripped prefix derivations in a fixed stack buffer, `char space[20]`. For each matched prefix, it appends `+` and the full prefix string before checking whether the buffer is full. A word containing several consecutive valid prefixes can make the append write past the end of `space`, causing a stack-buffer-overflow.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`spellprog` processes attacker-controlled words and dictionary lookup misses intermediate prefix-stripped forms.

## Proof

The reproduced trigger is a stdin word containing multiple valid prefixes:

`antibiodiselectroaaa`

The prefix stripping path is:

- `main()` reads the word from stdin.
- `main()` calls `trypref(ep, ".", 0)` at `usr.bin/spell/spellprog.c:332`.
- `trypref()` initializes `char space[20]`.
- `lookuppref()` matches `anti`, `bio`, `dis`, and `electro`.
- For each match, `trypref()` appends `+` and the prefix into `space`.
- The fourth append writes past `space[20]`.

The vulnerable sequence is:

```c
*pp++ = '+';
while ((*pp = *cp++))
	pp++;
if (pp - space >= sizeof(space))
	return (0);
```

The bounds check occurs after the copy. An ASan build with a dummy `pledge()` stub and a dictionary containing only `zzz` reported `stack-buffer-overflow` in `trypref()` at `usr.bin/spell/spellprog.c:636`, with `space` occupying `[64,84)` and the write occurring at offset `84`.

## Why This Is A Real Bug

The buffer size is 20 bytes, including the terminating NUL. The copied derivation for the demonstrated prefixes is:

`+anti+bio+dis+electro`

This requires more than 20 bytes including the final NUL. Because the existing capacity check runs only after `+` and the complete prefix have already been written, it cannot prevent the out-of-bounds stack write.

The input is attacker-controlled through stdin or documents processed by `spellprog`, and the reproduced impact is a crash. Unsanitized local execution also aborted on the same input.

## Fix Requirement

Check the remaining capacity in `space` before appending each `+prefix` derivation.

The required space for each append is:

- 1 byte for `+`
- `strlen(cp)` bytes for the prefix
- 1 byte for the terminating NUL

If that total does not fit in the remaining buffer, `trypref()` must return before writing.

## Patch Rationale

The patch adds a pre-copy capacity check:

```c
if (strlen(cp) + 2 > sizeof(space) - (pp - space))
	return (0);
```

This check executes before `*pp++ = '+'` and before copying the prefix string. It verifies that the current prefix plus separator plus NUL fits in the remaining portion of `space`, preserving the existing behavior of aborting prefix derivation when the local derivation buffer would be exhausted.

## Residual Risk

None

## Patch

```diff
diff --git a/usr.bin/spell/spellprog.c b/usr.bin/spell/spellprog.c
index f84ebae..e52c5c9 100644
--- a/usr.bin/spell/spellprog.c
+++ b/usr.bin/spell/spellprog.c
@@ -632,6 +632,8 @@ trypref(char *ep, char *a, int lev)
 	pp = space;
 	deriv[lev+1] = pp;
 	while ((cp = lookuppref(&bp, ep))) {
+		if (strlen(cp) + 2 > sizeof(space) - (pp - space))
+			return (0);
 		*pp++ = '+';
 		while ((*pp = *cp++))
 			pp++;
```