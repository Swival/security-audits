# Unescaped Macro Name Injects Generated Macro Wrapper

## Classification

Injection / generated JavaScript source injection.

Severity: High.

Confidence: Certain.

## Affected Locations

`src/bundler/entry_points.rs:450`

## Summary

`MacroEntryPoint::generate` interpolated attacker-controlled `function_name` bytes directly into generated JavaScript string literals and property lookups. A malicious macro export name containing a quote could terminate the generated string and inject executable JavaScript into the macro wrapper.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided scanner result and reproducer evidence.

## Preconditions

- The victim bundles a macro import from a malicious package.
- The malicious package author controls the exported macro name.
- The macro name reaches `MacroEntryPoint::generate` as `function_name`.

## Proof

Reachability was confirmed through the macro import path:

- Macro calls pass the imported name as `function_name` at `src/js_parser/visit/visit_expr.zig:1438`.
- `Macro::init` calls `load_macro_entry_point(..., function_name, ...)` at `src/js_parser_jsc/Macro.rs:470`.
- `load_macro_entry_point` calls `MacroEntryPoint::generate` at `src/jsc/VirtualMachine.rs:1323`.
- `MacroEntryPoint::generate` wrote `function_name` directly via `BStr::new(function_name)` into generated JavaScript at `src/bundler/entry_points.rs:497` and `src/bundler/entry_points.rs:514`.

A crafted macro import name such as:

```js
x' in Macros || (globalThis.pwned = 1) || 'x
```

produced generated wrapper code containing:

```js
if (!('x' in Macros || (globalThis.pwned = 1) || 'x' in Macros)) {
```

This executes attacker-controlled JavaScript during macro wrapper evaluation.

## Why This Is A Real Bug

The generated macro wrapper is JavaScript source code evaluated by the runtime. `function_name` is attacker-controlled when supplied by a malicious macro package/export name, but it was inserted into single-quoted JavaScript contexts without JavaScript string escaping.

Because `'` was not escaped, the attacker could break out of the intended string literal and turn data into executable wrapper code. This affects the non-`bun` macro wrapper path and also left unsafe interpolation in the `bun` path.

## Fix Requirement

Escape `function_name` according to the JavaScript quote context before inserting it into generated wrapper source.

Specifically:

- Use single-quote escaping for `Macros['...']` and `'...' in Macros`.
- Use double-quote escaping for error messages containing `"Macro '...' not found ..."`.
- Do not use raw `BStr::new(function_name)` in JavaScript string literal contexts.

## Patch Rationale

The patch precomputes escaped versions of `function_name` using `strings::format_escapes`:

- `function_name_single_quoted` uses `quote_char: b'\''`.
- `function_name_double_quoted` uses `quote_char: b'"'`.

It then replaces raw `BStr::new(function_name)` interpolation in generated JavaScript string contexts with the correctly escaped formatter. This preserves the intended lookup semantics while preventing quote termination and source injection.

## Residual Risk

None

## Patch

```diff
diff --git a/src/bundler/entry_points.rs b/src/bundler/entry_points.rs
index cd933457cd..9d5871922f 100644
--- a/src/bundler/entry_points.rs
+++ b/src/bundler/entry_points.rs
@@ -436,6 +436,20 @@ impl MacroEntryPoint {
         // for the (label, code) slices passed to `init_path_string`.
         let label_len = macro_label_.len();
         entry.code_buffer[..label_len].copy_from_slice(macro_label_);
+        let function_name_single_quoted = strings::format_escapes(
+            function_name,
+            strings::QuoteEscapeFormatFlags {
+                quote_char: b'\'',
+                ..Default::default()
+            },
+        );
+        let function_name_double_quoted = strings::format_escapes(
+            function_name,
+            strings::QuoteEscapeFormatFlags {
+                quote_char: b'"',
+                ..Default::default()
+            },
+        );
 
         let code_len: usize = 'brk: {
             if import_path.base == b"bun" {
@@ -456,8 +470,8 @@ impl MacroEntryPoint {
                      }}\n\
                      \n\
                      Bun.registerMacro({}, macro);",
-                    BStr::new(function_name),
-                    BStr::new(function_name),
+                    function_name_single_quoted,
+                    function_name_double_quoted,
                     macro_id,
                 )
                 .map_err(|_| bun_core::err!("NoSpaceLeft"))?;
@@ -494,8 +508,8 @@ impl MacroEntryPoint {
                         ..Default::default()
                     }
                 ),
-                BStr::new(function_name),
-                BStr::new(function_name),
+                function_name_single_quoted,
+                function_name_double_quoted,
                 bun_fmt::fmt_path_u8(
                     dir_to_use,
                     bun_fmt::PathFormatOptions {
@@ -511,7 +525,7 @@ impl MacroEntryPoint {
                     }
                 ),
                 macro_id,
-                BStr::new(function_name),
+                function_name_single_quoted,
             )
             .map_err(|_| bun_core::err!("NoSpaceLeft"))?;
             cursor.position() as usize
```