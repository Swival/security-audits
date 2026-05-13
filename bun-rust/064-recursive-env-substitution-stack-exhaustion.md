# recursive env substitution stack exhaustion

## Classification

Denial of service, medium severity, CWE-674/CWE-400 class uncontrolled recursion/resource exhaustion.

## Affected Locations

`src/ini/lib.rs:941`

## Summary

A malicious project `.npmrc` can force unbounded recursive environment-substitution parsing during `bun install`. Unquoted values containing deeply nested `${` sequences cause `parse_env_substitution` to recurse once per nested `$` with no depth limit, eventually exhausting the process stack and aborting installation.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Victim runs `bun install` in a malicious project.
- The malicious project author controls `.npmrc`.
- The `.npmrc` contains an unquoted value with deeply nested `${` tokens, such as `x=${${${...`.

## Proof

`load_npmrc` parses attacker-controlled `.npmrc` contents using `Parser::parse`.

For unquoted values, `prepare_str` scans bytes and calls `parse_env_substitution` when it sees `$` in value context. Inside `parse_env_substitution`, each unescaped `$` encountered within a `${...}` body recursively calls `parse_env_substitution` again before reaching a closing brace.

The reproduced minimized function confirmed the source-level failure mode: 1,000,000 repeated `${` sequences abort with:

```text
thread 'main' has overflowed its stack
```

This is reachable from normal `.npmrc` parsing during `bun install`.

## Why This Is A Real Bug

The recursion depth is directly controlled by bytes in a project-local `.npmrc`. No authentication, network access, or unusual runtime configuration is required beyond convincing a victim to run `bun install` in the malicious project.

Because Rust stack overflow aborts the process, the impact is a practical denial of service against installation.

## Fix Requirement

The parser must not recurse without a bounded depth on attacker-controlled `.npmrc` input. Acceptable fixes are:

- replace recursive substitution parsing with iterative parsing, or
- enforce a small maximum nesting depth and treat deeper input as non-substitution.

## Patch Rationale

The patch adds an explicit `depth` parameter to `parse_env_substitution` and caps recursion at `MAX_ENV_SUBSTITUTION_DEPTH = 32`.

The top-level call starts at depth `0`, and recursive calls pass `depth + 1`. If the depth limit is reached, the parser returns `Ok(None)`, preserving the existing behavior for malformed or unsupported substitution syntax: the value is left as literal text rather than expanded.

This bounds stack usage while retaining normal support for `${VAR}` and modest nested substitution cases.

## Residual Risk

None

## Patch

```diff
diff --git a/src/ini/lib.rs b/src/ini/lib.rs
index 1c3c13f5d9..979d35d3ed 100644
--- a/src/ini/lib.rs
+++ b/src/ini/lib.rs
@@ -768,7 +768,7 @@ mod draft {
                                     }
 
                                     if let Some(new_i) =
-                                        self.parse_env_substitution(val, i, i, &mut unesc)?
+                                        self.parse_env_substitution(val, i, i, 0, &mut unesc)?
                                     {
                                         // set to true so we heap alloc
                                         did_any_escape = true;
@@ -958,9 +958,14 @@ mod draft {
             val: &[u8],
             start: usize,
             i: usize,
+            depth: usize,
             unesc: &mut ArenaVec<'a, u8>,
         ) -> OOM<Option<usize>> {
+            const MAX_ENV_SUBSTITUTION_DEPTH: usize = 32;
             debug_assert!(val[i] == b'$');
+            if depth >= MAX_ENV_SUBSTITUTION_DEPTH {
+                return Ok(None);
+            }
             let mut esc = false;
             if i + b"{}".len() < val.len() && val[i + 1] == b'{' {
                 let mut found_closing = false;
@@ -970,7 +975,7 @@ mod draft {
                         b'\\' => esc = !esc,
                         b'$' => {
                             if !esc {
-                                return self.parse_env_substitution(val, start, j, unesc);
+                                return self.parse_env_substitution(val, start, j, depth + 1, unesc);
                             }
                         }
                         b'{' => {
```