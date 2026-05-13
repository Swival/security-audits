# Template Literal Macro Invocation Panics

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

- `src/js_parser_jsc/Macro.rs:1036`
- `src/js_parser_jsc/Macro.rs:1039`

## Summary

An imported macro invoked as a template literal reaches `Runner::run` with `caller.data == ExprData::ETemplate(_)`. That match arm unconditionally panics with `panic!("TODO: support template literals in macros")`.

Because release profile settings use `panic = "abort"`, this aborts the bundler process instead of producing a recoverable macro diagnostic.

## Provenance

- Verified by reproduced source-path analysis.
- Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The victim bundles source that invokes an imported macro as a template literal.
- The macro call site is in attacker-controlled project source outside `node_modules`.
- The macro import is marked with `with/assert { type: "macro" }` and resolves successfully.

## Proof

A source file such as:

```js
import { m } from "./macro" with { type: "macro" };
m`x`;
```

is recorded as a macro import by `src/js_parser/p.zig:2710`.

When the invocation is processed, `MacroContext::call` reaches `Runner::run`. `Runner::run` matches the parsed caller expression:

```rust
ExprData::ETemplate(_) => {
    panic!("TODO: support template literals in macros");
}
```

This is present in `src/js_parser_jsc/Macro.rs:1036` through `src/js_parser_jsc/Macro.rs:1039`.

`Cargo.toml:151` and `Cargo.toml:154` configure `panic = "abort"`, so the panic terminates the process.

## Why This Is A Real Bug

The caller expression is derived from bundled source. A template literal macro invocation is valid enough to reach the macro call path, but the implementation handles it with an unconditional panic instead of an error.

In affected release builds, the panic is not recoverable because panics abort. This gives attacker-controlled bundled source a deterministic way to terminate the bundler process.

The broader malicious-package scenario is constrained because macro call sites inside `node_modules` are blocked by `p.source.path.isNodeModule()` at `src/js_parser/visit/visit_expr.zig:406`. The bug remains security-relevant for build services or workflows that bundle attacker-controlled project files outside `node_modules`.

## Fix Requirement

The `ExprData::ETemplate(_)` arm must not panic. It must emit a macro diagnostic and return `MacroError::MacroFailed`, allowing normal error handling to stop the build without aborting the process.

## Patch Rationale

The patch replaces the unconditional panic with `log.add_error_fmt(...)` and `return Err(MacroError::MacroFailed)`.

This preserves the current behavior that template literal macro invocations are unsupported, but changes the failure mode from process abort to a recoverable build error.

## Residual Risk

None

## Patch

```diff
diff --git a/src/js_parser_jsc/Macro.rs b/src/js_parser_jsc/Macro.rs
index cb1be7cee3..352595e05c 100644
--- a/src/js_parser_jsc/Macro.rs
+++ b/src/js_parser_jsc/Macro.rs
@@ -1034,9 +1034,12 @@ impl Runner {
                 }
             }
             ExprData::ETemplate(_) => {
-                // PORT NOTE: faithful port — Zig source is
-                // `@panic("TODO: support template literals in macros");`
-                panic!("TODO: support template literals in macros");
+                log.add_error_fmt(
+                    Some(source),
+                    caller.loc,
+                    format_args!("template literal macro invocations are not supported"),
+                );
+                return Err(MacroError::MacroFailed);
             }
             _ => {
                 panic!("Unexpected caller type");
```