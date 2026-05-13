# parseArgs panics on throwing argument coercion

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/runtime/node/util/parse_args.rs:42`

## Summary

`node:util.parseArgs` accepted `config.args` after validating only that it was an array. During tokenization, each array element was coerced with `JSValue::to_bun_string(global)` through `ValueRef::as_bun_string`. That helper used `expect("unexpected exception")`, so a JavaScript value whose string coercion threw caused a Rust panic instead of returning a JavaScript exception.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Host exposes `parseArgs` to attacker-controlled JavaScript input.
- Attacker can supply `config.args` containing a non-string value whose `ToString` coercion throws.

## Proof

Minimal triggering input:

```js
const { parseArgs } = require("node:util");

parseArgs({
  args: [{ toString() { throw new Error("boom"); } }],
  allowPositionals: true,
});
```

Observed runtime behavior before the patch:

- Process exits with code `132`.
- Output includes `panic(main thread): unexpected exception`.
- JavaScript `try/catch` cannot recover because the exception is converted into a host panic.

Root cause path:

- `parse_args` validates `config.args` only with `validators::validate_array`.
- `tokenize_args` fetches each element with `ArgsSlice::get`.
- The element is wrapped as `ValueRef::Jsvalue`.
- `tokenize_args` calls `arg_ref.as_bun_string(global)`.
- `ValueRef::as_bun_string` calls `str.to_bun_string(global).expect("unexpected exception")`.
- A throwing `toString()` returns an exception result, and `expect` panics.

## Why This Is A Real Bug

JavaScript argument coercion is observable and can throw. Host bindings must propagate that exception as a `JsResult` error. Panicking crosses the JavaScript exception boundary and terminates the process, so an attacker-controlled argument array can deny service to any embedding or application path that exposes `parseArgs` on untrusted input.

## Fix Requirement

Replace the infallible `ValueRef::as_bun_string` conversion with a fallible `JsResult<String>` return and propagate `to_bun_string` failures with `?` at all call sites.

## Patch Rationale

The patch changes `ValueRef::as_bun_string` from:

```rust
str.to_bun_string(global).expect("unexpected exception")
```

to:

```rust
str.to_bun_string(global)
```

and updates call sites to use `?`. This preserves normal parsing behavior while correctly returning JavaScript exceptions when coercion fails.

`RawNameFormatter` is also adjusted to store a precomputed `String` rather than calling fallible conversion inside `fmt::Display`, where `JsResult` cannot be propagated.

## Residual Risk

None

## Patch

```diff
diff --git a/src/runtime/node/util/parse_args.rs b/src/runtime/node/util/parse_args.rs
index e4c503df36..6f2e032971 100644
--- a/src/runtime/node/util/parse_args.rs
+++ b/src/runtime/node/util/parse_args.rs
@@ -35,10 +35,10 @@ enum ValueRef {
 }
 
 impl ValueRef {
-    pub fn as_bun_string(&self, global: &JSGlobalObject) -> String {
+    pub fn as_bun_string(&self, global: &JSGlobalObject) -> JsResult<String> {
         match self {
-            ValueRef::Jsvalue(str) => str.to_bun_string(global).expect("unexpected exception"),
-            ValueRef::Bunstr(str) => *str,
+            ValueRef::Jsvalue(str) => str.to_bun_string(global),
+            ValueRef::Bunstr(str) => Ok(*str),
         }
     }
 
@@ -105,16 +105,16 @@ struct OptionToken {
     raw: ValueRef,
 }
 
-struct RawNameFormatter<'a> {
+struct RawNameFormatter {
     token: OptionToken,
-    global: &'a JSGlobalObject,
+    raw: String,
 }
 
-impl<'a> fmt::Display for RawNameFormatter<'a> {
+impl fmt::Display for RawNameFormatter {
     /// Formats the raw name of the arg (includes any dashes and excludes inline values)
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         let token = &self.token;
-        let raw = token.raw.as_bun_string(self.global);
+        let raw = self.raw;
         if let Some(optgroup_idx) = token.optgroup_idx {
             let i = optgroup_idx as usize;
             raw.substring_with_len(i, i + 1).fmt(f)
@@ -139,7 +139,7 @@ impl OptionToken {
     /// Returns the raw name of the arg (includes any dashes and excludes inline values), as a JSValue
     fn make_raw_name_js_value(&self, global: &JSGlobalObject) -> JsResult<JSValue> {
         if let Some(optgroup_idx) = self.optgroup_idx {
-            let raw = self.raw.as_bun_string(global);
+            let raw = self.raw.as_bun_string(global)?;
             let i = optgroup_idx as usize;
             let mut buf = [0u8; 8];
             let str = {
@@ -156,12 +156,12 @@ impl OptionToken {
                     self.raw.as_js_value(global)
                 }
                 OptionParseType::ShortOptionAndValue => {
-                    let raw = self.raw.as_bun_string(global);
+                    let raw = self.raw.as_bun_string(global)?;
                     let substr = raw.substring_with_len(0, 2);
                     substr.to_js(global)
                 }
                 OptionParseType::LongOptionAndValue => {
-                    let raw = self.raw.as_bun_string(global);
+                    let raw = self.raw.as_bun_string(global)?;
                     let equal_index = raw.index_of_ascii_char(b'=').unwrap();
                     let substr = raw.substring_with_len(0, equal_index);
                     substr.to_js(global)
@@ -220,12 +220,13 @@ fn get_default_args(global: &JSGlobalObject) -> JsResult<ArgsSlice> {
 
 /// In strict mode, throw for possible usage errors like "--foo --bar" where foo was defined as a string-valued arg
 fn check_option_like_value(global: &JSGlobalObject, token: OptionToken) -> JsResult<()> {
-    if !token.inline_value && is_option_like_value(&token.value.as_bun_string(global)) {
-        let raw_name = RawNameFormatter { token, global };
+    if !token.inline_value && is_option_like_value(&token.value.as_bun_string(global)?) {
+        let raw = token.raw.as_bun_string(global)?;
+        let raw_name = RawNameFormatter { token, raw };
 
         // Only show short example if user used short option.
         let err: JSValue;
-        if token.raw.as_bun_string(global).has_prefix_comptime(b"--") {
+        if raw.has_prefix_comptime(b"--") {
             err = global.to_type_error(
                 bun_jsc::ErrorCode::PARSE_ARGS_INVALID_OPTION_VALUE,
                 format_args!(
@@ -233,7 +234,7 @@ fn check_option_like_value(global: &JSGlobalObject, token: OptionToken) -> JsRes
                 ),
             );
         } else {
-            let token_name = token.name.as_bun_string(global);
+            let token_name = token.name.as_bun_string(global)?;
             err = global.to_type_error(
                 bun_jsc::ErrorCode::PARSE_ARGS_INVALID_OPTION_VALUE,
                 format_args!(
@@ -261,7 +262,10 @@ fn check_option_usage(
                     if token.negative {
                         // the option was found earlier because we trimmed 'no-' from the name, so we throw
                         // the expected unknown option error.
-                        let raw_name = RawNameFormatter { token, global };
+                        let raw_name = RawNameFormatter {
+                            token,
+                            raw: token.raw.as_bun_string(global)?,
+                        };
                         let err = global.to_type_error(
                             bun_jsc::ErrorCode::PARSE_ARGS_UNKNOWN_OPTION,
                             format_args!("Unknown option '{raw_name}'"),
@@ -283,7 +287,7 @@ fn check_option_usage(
                             } else {
                                 ""
                             },
-                            token.name.as_bun_string(global),
+                            token.name.as_bun_string(global)?,
                         ),
                     );
                     return Err(global.throw_value(err));
@@ -306,7 +310,7 @@ fn check_option_usage(
                             } else {
                                 ""
                             },
-                            token.name.as_bun_string(global),
+                            token.name.as_bun_string(global)?,
                         ),
                     );
                     return Err(global.throw_value(err));
@@ -314,7 +318,10 @@ fn check_option_usage(
             }
         }
     } else {
-        let raw_name = RawNameFormatter { token, global };
+        let raw_name = RawNameFormatter {
+            token,
+            raw: token.raw.as_bun_string(global)?,
+        };
 
         let err = if allow_positionals {
             global.to_type_error(
@@ -349,7 +356,7 @@ fn store_option(
     options: &[OptionDefinition],
     values: JSValue,
 ) -> JsResult<()> {
-    let key = option_name.as_bun_string(global);
+    let key = option_name.as_bun_string(global)?;
     if key.eql_comptime(b"__proto__") {
         return Ok(());
     }
@@ -527,7 +534,7 @@ fn tokenize_args(
     let mut index: u32 = 0;
     while index < num_args {
         let arg_ref = ValueRef::Jsvalue(args.get(global, index)?);
-        let arg = arg_ref.as_bun_string(global);
+        let arg = arg_ref.as_bun_string(global)?;
 
         let token_rawtype = classify_token(&arg, options);
         bun_output::scoped_log!(
@@ -798,7 +805,7 @@ impl<'a> ParseArgsState<'a> {
                         bun_jsc::ErrorCode::PARSE_ARGS_UNEXPECTED_POSITIONAL,
                         format_args!(
                             "Unexpected argument '{}'. This command does not take positional arguments",
-                            value.as_bun_string(global),
+                            value.as_bun_string(global)?,
                         ),
                     );
                     return Err(global.throw_value(err));
```