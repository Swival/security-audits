# Infinite Loop On Empty Starred Backreference

## Classification

Logic error, medium severity.

## Affected Locations

`modules/filters/regexp.c:538`

## Summary

A starred backreference to an empty captured group can make the sed regexp matcher loop forever. When the captured group length is zero, the `CBACK | STAR` handler repeatedly compares zero bytes and advances the input pointer by zero bytes, so the loop never terminates.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The regexp contains a valid starred backreference.
- The referenced capture group matched an empty string.
- Matching reaches the `CBACK | STAR` bytecode path in `_advance()`.

## Proof

`sed_compile()` emits `CBACK` for valid backreferences and allows `*` to apply to the previous backreference, producing `CBACK | STAR`.

For a pattern such as:

```text
s/\(\)\1*/x/
```

the empty capture records identical start and end pointers:

- `CBRA` stores `vars->braslist[0] = lp`.
- `CKET` stores `vars->braelist[0] = lp`.

The starred backreference handler then computes:

```c
ct = vars->braelist[epint] - bbeg;
```

Because both pointers are equal, `ct == 0`.

Before the patch, the loop was:

```c
while (ecmp(bbeg, lp, ct))
    lp += ct;
```

With `ct == 0`, `ecmp(bbeg, lp, 0)` is equivalent to `strncmp(..., 0) == 0`, which is always true, and `lp += ct` does not advance `lp`. The matcher therefore remains in the loop indefinitely.

This is reachable through normal sed matching because `sed1.c` calls `sed_step()` from `match()` at `modules/filters/sed1.c:659`, including substitution and address matching paths.

## Why This Is A Real Bug

The loop termination condition depends on either `ecmp()` becoming false or `lp` advancing. For a zero-length backreference, neither can happen:

- The comparison length is zero, so the comparison always succeeds.
- The pointer increment is zero, so the matcher state does not change.
- The loop has no independent bound or break condition.

This creates a practical denial-of-service condition for inputs that evaluate a regexp containing a starred backreference to an empty capture.

## Fix Requirement

The `CBACK | STAR` case must special-case zero-length backreferences before entering the repetition loop.

A zero-length starred backreference should behave as matching zero repetitions and continue with the remaining expression, rather than attempting to greedily consume input.

## Patch Rationale

The patch adds:

```c
if (ct == 0)
    continue;
```

immediately after computing the captured backreference length and advancing past the backreference operand.

This is correct because:

- `X*` may match zero occurrences.
- A zero-length `X` cannot consume input, so repeating it greedily is meaningless.
- Continuing to the next bytecode preserves matcher progress.
- Non-empty backreferences retain the existing greedy repetition and backtracking behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/regexp.c b/modules/filters/regexp.c
index 4acccca..df43dff 100644
--- a/modules/filters/regexp.c
+++ b/modules/filters/regexp.c
@@ -535,6 +535,8 @@ static int _advance(char *lp, char *ep, step_vars_storage *vars)
             bbeg = vars->braslist[epint];
             ct = vars->braelist[epint] - bbeg;
             ep++;
+            if (ct == 0)
+                continue;
             curlp = lp;
             while (ecmp(bbeg, lp, ct))
                 lp += ct;
```