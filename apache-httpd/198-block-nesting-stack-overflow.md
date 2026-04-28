# block nesting stack overflow

## Classification

Memory safety, medium severity.

## Affected Locations

`modules/filters/sed0.c:296`

## Summary

The sed script compiler stores nested `{` block end pointers in `commands->cmpend[commands->depth++]` without first checking that `commands->depth` is within the fixed `SED_DEPTH` capacity. A sed script with more than `SED_DEPTH` nested `{` commands writes past the `cmpend` array during normal compilation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

The sed script contains more nested `{` blocks than `SED_DEPTH`.

## Proof

In `fcomp`, each parsed `{` command reaches:

```c
commands->cmpend[commands->depth++] = &commands->rep->lb1;
```

Before the patch, there is no check that `commands->depth < SED_DEPTH` before this write.

A practical trigger is a sed script with 21 nested opens before any close, for example 21 lines containing only `{`. The first 20 writes fill `cmpend[0]` through `cmpend[19]`; the 21st arrives with `commands->depth == 20`, so `cmpend[20]` writes past the declared array.

The write occurs before `alloc_reptr()` is called at `modules/filters/sed0.c:299`, so normal allocation and error paths do not prevent it.

## Why This Is A Real Bug

This is an out-of-bounds write during sed script compilation. The script does not need to be otherwise valid: unmatched opens are detected later through finalization state, after the invalid store has already occurred.

The overflow corrupts adjacent command state in memory. In the visible layout, adjacent state includes `ptrspace`, which is later used by `alloc_reptr()` at `modules/filters/sed0.c:1016` and by evaluation as the command-list head. This makes the issue memory-unsafe undefined behavior reachable through attacker-controlled sed script input.

## Fix Requirement

Check `commands->depth` against `SED_DEPTH` before writing to `commands->cmpend`, and fail compilation if the nesting limit has already been reached.

## Patch Rationale

The patch adds a guard immediately before the vulnerable store:

```c
if (commands->depth >= SED_DEPTH) {
    command_errf(commands, SEDERR_TMOMES);
    return -1;
}
```

This preserves existing behavior for valid scripts while rejecting excessive nesting before any out-of-bounds access occurs. The selected error path matches the existing “too many opens”/nesting error semantics already used for unmatched block depth finalization.

## Residual Risk

None

## Patch

```diff
diff --git a/modules/filters/sed0.c b/modules/filters/sed0.c
index a044f64..1a71931 100644
--- a/modules/filters/sed0.c
+++ b/modules/filters/sed0.c
@@ -295,6 +295,10 @@ swit:
         case '{':
             commands->rep->command = BCOM;
             commands->rep->negfl = !(commands->rep->negfl);
+            if (commands->depth >= SED_DEPTH) {
+                command_errf(commands, SEDERR_TMOMES);
+                return -1;
+            }
             commands->cmpend[commands->depth++] = &commands->rep->lb1;
             commands->rep = alloc_reptr(commands);
             commands->rep->ad1 = p;
```