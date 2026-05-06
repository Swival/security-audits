# suffix substitution underflows match offset

## Classification

Medium severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`make/varmodifiers.c:523`

## Summary

Suffix-anchored `:S` substitutions can compute a match pointer using an underflowed `size_t` subtraction when the stripped left-hand pattern is longer than the current word. The resulting pointer is outside the word object and can be passed to `strncmp`, causing an out-of-bounds read during make variable expansion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `make` expands an attacker-controlled variable modifier.
- The attacker controls a makefile or equivalent input that can trigger an `:S` modifier.
- The `:S` left-hand side ends in `$`.
- The stripped left-hand side length is greater than the target word length.

## Proof

`common_get_patternarg` treats a trailing `$` in an `:S` left-hand side as a suffix anchor. It strips the `$` by decrementing `pattern->leftLen` and sets `VAR_MATCH_END`.

`VarModify` then applies `VarSubstitute` to each word. In the suffix-only branch, the vulnerable code computes:

```c
cp = word->s + (wordLen - pattern->leftLen);
```

When `wordLen` is shorter than `pattern->leftLen`, both operands are `size_t`, so the subtraction underflows before pointer addition. For example, with `wordLen = 3` and `pattern->leftLen = 4`, the computed offset wraps to a very large value.

The later guard:

```c
if (cp >= word->s &&
    strncmp(cp, pattern->lhs, pattern->leftLen) == 0)
```

does not prevent the bug because the out-of-object pointer has already been computed. Optimized builds can proceed to `strncmp` with an invalid pointer, causing an out-of-bounds read and potential crash.

## Why This Is A Real Bug

The vulnerable path is reachable from attacker-controlled makefile syntax using an `:S` modifier whose left-hand side ends in `$`. The parser explicitly supports this suffix anchor form and shortens the stored pattern length. If the attacker chooses a pattern longer than the word being modified, the suffix-match offset underflows.

This is a memory-safety error, not just an incorrect comparison. The invalid pointer is derived before the attempted range check, and `strncmp` may read far outside the word allocation.

## Fix Requirement

Check `wordLen >= pattern->leftLen` before subtracting `pattern->leftLen` from `wordLen` or comparing the candidate suffix.

## Patch Rationale

The patch makes the suffix candidate pointer conditional on the length check:

```c
cp = wordLen >= pattern->leftLen ?
    word->s + (wordLen - pattern->leftLen) : NULL;
if (cp != NULL &&
    strncmp(cp, pattern->lhs, pattern->leftLen) == 0) {
```

This preserves existing behavior when the word is long enough to contain the suffix and safely falls through to the no-substitution path when it is not. The subtraction and pointer addition are no longer evaluated for impossible suffix matches.

## Residual Risk

None

## Patch

```diff
diff --git a/make/varmodifiers.c b/make/varmodifiers.c
index 2c2e352..72fd274 100644
--- a/make/varmodifiers.c
+++ b/make/varmodifiers.c
@@ -495,8 +495,9 @@ VarSubstitute(struct Name *word, bool addSpace, Buffer buf,
 	     * characters from the end of the word) and see if it does. Note
 	     * that because the $ will be left at the end of the lhs, we have
 	     * to use strncmp.	*/
-	    cp = word->s + (wordLen - pattern->leftLen);
-	    if (cp >= word->s &&
+	    cp = wordLen >= pattern->leftLen ?
+		word->s + (wordLen - pattern->leftLen) : NULL;
+	    if (cp != NULL &&
 		strncmp(cp, pattern->lhs, pattern->leftLen) == 0) {
 		/* Match found. If we will place characters in the buffer,
 		 * add a space before hand as indicated by addSpace, then
```