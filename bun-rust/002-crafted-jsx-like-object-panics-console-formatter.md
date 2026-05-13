# Crafted JSX-Like Object Panics Console Formatter

## Classification

Denial of service, medium severity.

## Affected Locations

`src/jsc/ConsoleObject.rs:5392`

## Summary

A crafted JavaScript object with a React `$$typeof` symbol and a primitive `props` value is classified as JSX and routed to the JSX console formatter. The formatter assumed `props` was always an object and called `props.get_object().unwrap()`. For primitive `props`, this returned `None` and panicked, terminating the Bun process.

## Provenance

Reported and verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Bun formats attacker-controlled objects through `console.*` or inspect-style formatting.

## Proof

A minimal attacker-controlled value is:

```js
console.log({
  $$typeof: Symbol.for("react.element"),
  type: "div",
  props: 1,
});
```

Execution path:

- `format2()` obtains a formatter tag with `formatter::Tag::get()`.
- `Tag::get_advanced()` treats any non-proxy object whose own `$$typeof` matches `Symbol.for("react.element")`, `Symbol.for("react.transitional.element")`, or `Symbol.for("react.fragment")` as `TagPayload::JSX`.
- `Formatter::print_as()` dispatches `Tag::JSX` to `print_jsx()`.
- `print_jsx()` reads `props` and previously executed `props.get_object().unwrap()` without checking that `props` was an object.
- With `props: 1`, `get_object()` returns `None`; `unwrap()` panics and terminates the process.

## Why This Is A Real Bug

The JSX classifier only validates the React marker symbol, not the structural invariants of a real React element. JavaScript objects are attacker-controlled and can contain arbitrary `props` values. Therefore a primitive `props` value reaches the unchecked unwrap through normal console formatting. A panic in the console formatter is process-terminating denial of service under the stated precondition.

## Fix Requirement

Do not unwrap `props.get_object()` unless `props` is known to be an object. If `props` is absent or non-object, JSX formatting must degrade safely, for example by emitting a self-closing tag or falling back to generic object formatting.

## Patch Rationale

The patch replaces the unchecked unwrap with an `if let`/`let Some(...) else` guard. When `props` is not an object, the formatter writes a self-closing JSX tag, propagates any writer failure into `self.failed`, and returns successfully. This preserves formatting for valid JSX-like values while preventing primitive `props` from causing a Rust panic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/jsc/ConsoleObject.rs b/src/jsc/ConsoleObject.rs
index 2127c91204..77b81c21ee 100644
--- a/src/jsc/ConsoleObject.rs
+++ b/src/jsc/ConsoleObject.rs
@@ -5388,8 +5388,13 @@ pub mod formatter {
                 let _qs = defer_restore!(self.quote_strings, prev_quote_strings);
                 self.quote_strings = true;
 
-                // JSX props are always objects.
-                let props_obj = props.get_object().unwrap();
+                let Some(props_obj) = props.get_object() else {
+                    writer.write_all(b" />");
+                    if writer.failed {
+                        self.failed = true;
+                    }
+                    return Ok(());
+                };
                 let mut props_iter = jsc::JSPropertyIterator::init(
                     self.global_this,
                     props_obj,
```