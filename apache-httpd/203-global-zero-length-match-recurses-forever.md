# Global Zero-Length Match Recurses Forever

## Classification

Logic error; denial of service via unbounded recursion.

Confidence: certain.

## Affected Locations

`server/util_regex.c:174`

## Summary

`ap_rxplus_exec()` recursively applies global substitutions when `AP_REG_MULTI` is set. If the compiled regular expression can match an empty string, the matched length is zero, so the computed `remainder` does not advance. The recursive call receives the same input position, repeats the same zero-length match, and recurses until stack exhaustion.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the supplied source and reproducer evidence.

## Preconditions

- The pattern is compiled by `ap_rxplus_compile()`.
- The substitution has the `g` flag, setting `AP_REG_MULTI`.
- The regular expression can match a zero-length string.
- Caller-controlled or otherwise reachable input is passed to `ap_rxplus_exec()`.

## Proof

A minimal trigger is:

```text
s/^/X/g
```

executed against any string, including:

```text
abc
```

or the empty string.

Execution path:

- `ap_rxplus_exec()` calls `ap_regexec()` at `server/util_regex.c:149`.
- The regex `^` can match zero bytes at the beginning of the string.
- `startl` becomes `0`.
- `oldl = rx->pmatch[0].rm_eo - startl` becomes `0`.
- `remainder = pattern + startl + oldl` still points to the original input.
- Because `AP_REG_MULTI` is set, `ap_rxplus_exec()` recurses on the unchanged `remainder`.
- The recursive call observes the same zero-length match at offset `0`.
- No progress is made, causing unbounded recursion and eventual denial of service.

## Why This Is A Real Bug

Global substitution logic must either advance after a zero-length match or stop processing to guarantee forward progress. The original code does neither. For zero-length matches, `remainder` is identical to the current input position, so recursion is not bounded by input length.

This is reachable through normal substitution syntax using the `g` flag and a valid zero-length-matching regex such as `^`.

## Fix Requirement

When applying global substitutions, `ap_rxplus_exec()` must not recursively process the same input position after a zero-length match.

Acceptable fixes include:

- Stop global recursion when the match length is zero.
- Or advance the remainder safely before continuing.

The applied fix uses the stop-recursion behavior.

## Patch Rationale

The patch changes the recursive global substitution condition from:

```c
if (rx->flags & AP_REG_MULTI) {
```

to:

```c
if ((rx->flags & AP_REG_MULTI) && oldl > 0) {
```

This preserves existing global substitution behavior for non-empty matches while preventing recursion when the current match consumed zero bytes. Since a zero-length match does not advance `remainder`, suppressing recursion is sufficient to eliminate the denial-of-service condition.

## Residual Risk

None

## Patch

```diff
diff --git a/server/util_regex.c b/server/util_regex.c
index 5405f8d..c4056a7 100644
--- a/server/util_regex.c
+++ b/server/util_regex.c
@@ -162,7 +162,7 @@ AP_DECLARE(int) ap_rxplus_exec(apr_pool_t *pool, ap_rxplus_t *rx,
         newl = strlen(*newpattern);
         diffsz = newl - oldl;
         remainder = pattern + startl + oldl;
-        if (rx->flags & AP_REG_MULTI) {
+        if ((rx->flags & AP_REG_MULTI) && oldl > 0) {
             /* recurse to do any further matches */
             ret += ap_rxplus_exec(pool, rx, remainder, &subs);
             if (ret > 1) {
```