# Dotted Namespace Recursion Exhausts Parser Stack

## Classification

Denial of service, medium severity.

## Affected Locations

`src/js_parser/parse/parse_typescript.rs:216`

## Summary

TypeScript dotted namespace parsing recurses once per namespace segment without checking parser recursion depth. Attacker-controlled TypeScript such as `namespace a.a.a...a {}` can exhaust the Rust stack and crash the parse worker/process.

## Provenance

Verified and patched finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

TypeScript parsing accepts attacker-controlled source.

## Proof

The parser handles `namespace foo {}` in `parse_type_script_namespace_stmt`. When the current token is `T::TDot`, it consumes the dot, creates namespace-scope parse options, and directly calls `parse_type_script_namespace_stmt` again for the next dotted segment.

The recursive call path does not re-enter the existing stack/depth checks in statement parsing or expression parsing before adding another Rust stack frame. Therefore, each additional dotted namespace segment adds one parser call frame.

Reproducer:

```sh
python3 -c 'n=800; open("/tmp/ns.ts","w").write("namespace "+".".join(["a"]*n)+" {}\n")'
bun build /tmp/ns.ts --outfile=/tmp/ns.js
```

Observed result: exit code `139` / segmentation fault. Inputs around 700 dotted segments completed, while 800+ crashed, consistent with stack exhaustion.

## Why This Is A Real Bug

This is not just a syntax error or rejected malformed input. Dotted namespaces are valid TypeScript syntax, and the parser follows a recursive implementation strategy for them. Because attacker-controlled source can choose the number of dotted segments, an attacker can force unbounded parser recursion until the parse worker overflows its stack and denies service.

Existing parser stack checks are present elsewhere, including statement and expression parsing, but this dotted namespace path bypasses them before recursing.

## Fix Requirement

Before recursively parsing the next dotted namespace segment, the parser must either:

- enforce the existing recursion safety check, or
- parse dotted namespace segments iteratively.

The fix must prevent one unchecked Rust stack frame per attacker-controlled dotted segment.

## Patch Rationale

The patch adds `p.stack_check.is_safe_to_recurse()` immediately before the recursive `parse_type_script_namespace_stmt` call on the dotted namespace path.

This preserves current parser behavior for normal inputs while converting excessive dotted namespace depth into a controlled `StackOverflow` parser error instead of process stack exhaustion.

## Residual Risk

None

## Patch

```diff
diff --git a/src/js_parser/parse/parse_typescript.rs b/src/js_parser/parse/parse_typescript.rs
index baa67dd3e9..057b77e39a 100644
--- a/src/js_parser/parse/parse_typescript.rs
+++ b/src/js_parser/parse/parse_typescript.rs
@@ -220,6 +220,9 @@ impl<'a, const TYPESCRIPT: bool, J: JsxT, const SCAN_ONLY: bool> P<'a, TYPESCRIP
                 is_typescript_declare: opts.is_typescript_declare,
                 ..ParseStatementOptions::default()
             };
+            if !p.stack_check.is_safe_to_recurse() {
+                return Err(err!("StackOverflow"));
+            }
             stmts.push(p.parse_type_script_namespace_stmt(dot_loc, &mut _opts)?);
         } else if opts.is_typescript_declare && p.lexer.token != T::TOpenBrace {
             p.lexer.expect_or_insert_semicolon()?;
```