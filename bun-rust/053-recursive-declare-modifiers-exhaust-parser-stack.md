# Recursive Declare Modifiers Exhaust Parser Stack

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/js_parser/parse/parse_property.rs:311`

## Summary

TypeScript class property parsing handled `declare` as a contextual modifier by recursively calling `parse_property` without first recording that `declare` had already been seen. An attacker controlling parsed TypeScript class source could provide many consecutive `declare` modifiers, causing one recursive Rust stack frame per token and eventually aborting bundling or transpilation through stack exhaustion.

## Provenance

Verified from supplied source, reproduced behavior summary, and patch.

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

TypeScript parsing of attacker-supplied class source is enabled.

## Proof

A class property such as:

```ts
class C { declare declare declare x: T }
```

reaches the contextual modifier path in `parse_property`.

The parser consumes the current identifier-like token, identifies `declare`, and enters the `PDeclare` arm. When `opts.is_class`, TypeScript is enabled, and `raw == b"declare"`, the vulnerable code recursively calls:

```rust
p.parse_property(kind, opts, None)?
```

Because the old branch did not set `opts.declare_range` or any equivalent state before recursing, the next `declare` token re-enters the same arm. Repeating `declare` repeats recursion once per token.

`parse_property` has no stack-depth guard at entry, and this recursion remains inside class-property parsing, bypassing existing statement/expression stack checks. A sufficiently long modifier sequence exhausts the Rust process stack.

## Why This Is A Real Bug

The input is syntactically attacker-controlled TypeScript source, and the failure mode is process stack exhaustion rather than a normal parse error. This can terminate bundling or transpilation for consumers that parse untrusted or semi-trusted TypeScript.

The issue is not theoretical because each additional `declare` token creates another recursive `parse_property` invocation before the parser can return or reject the duplicate modifier.

## Fix Requirement

The parser must not recurse indefinitely over repeated `declare` modifiers. It must either parse repeated modifiers iteratively with bounded state or reject duplicate `declare` before making the recursive call.

## Patch Rationale

The patch rejects a duplicate `declare` modifier before recursion:

```rust
if !opts.declare_range.is_empty() {
    p.lexer.unexpected()?;
    return Err(err!("SyntaxError"));
}

opts.declare_range = name_range;
```

This mirrors the existing stateful handling used for other TypeScript class modifiers such as `abstract`. After the first `declare`, `opts.declare_range` records that the modifier has been consumed. A second consecutive `declare` now produces a handled syntax error instead of adding another recursive stack frame.

The patch also preserves the existing downstream behavior that uses `opts.declare_range` to reject initialized `declare` class fields.

## Residual Risk

None

## Patch

```diff
diff --git a/src/js_parser/parse/parse_property.rs b/src/js_parser/parse/parse_property.rs
index dc5001fb75..ca1cbc1e39 100644
--- a/src/js_parser/parse/parse_property.rs
+++ b/src/js_parser/parse/parse_property.rs
@@ -431,6 +431,12 @@ impl<'a, const TYPESCRIPT: bool, J: JsxT, const SCAN_ONLY: bool> P<'a, TYPESCRIP
                                             && Self::IS_TYPESCRIPT_ENABLED
                                             && raw == b"declare"
                                         {
+                                            if !opts.declare_range.is_empty() {
+                                                p.lexer.unexpected()?;
+                                                return Err(err!("SyntaxError"));
+                                            }
+
+                                            opts.declare_range = name_range;
                                             let scope_index = p.scopes_in_order.len();
                                             if let Some(_prop) =
                                                 p.parse_property(kind, opts, None)?
```