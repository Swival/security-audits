# Unresolved Color Parsing Bypasses Nesting Limit

## Classification

Denial of service, medium severity. Confidence: certain.

## Affected Locations

`src/css/properties/custom.rs:746`

## Summary

Attacker-controlled CSS custom or unparsed property values can trigger unbounded recursive parsing through nested `rgb()`/`hsl()` alpha functions. The unresolved color parser reset token-list nesting depth to `0` when parsing slash alpha values, bypassing the intended `depth > 500` guard and allowing parser stack exhaustion.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The bundler parses attacker-supplied CSS.
- The attacker-controlled CSS reaches custom property or unparsed property parsing.
- The CSS contains deeply nested `rgb()` or `hsl()` functions in slash alpha positions.

## Proof

`CustomProperty::parse` and `UnparsedProperty::parse` both parse attacker-controlled values through `TokenList::parse(..., 0)`.

`TokenList::parse_into` enforces the nesting guard only when `depth > 500`, and normal nested functions recurse with `depth + 1`.

When `TokenList::parse_into` encounters a function token, it first attempts unresolved color parsing through:

```rust
input.try_parse(|i| UnresolvedColor::parse(i, f, options))
```

`UnresolvedColor::parse` did not receive the caller depth. For `rgb()` and `hsl()`, slash alpha parsing used:

```rust
TokenListFns::parse(i, options, 0)
```

at the alpha parse sites, resetting depth for each nested unresolved color alpha expression.

A repeated nesting pattern such as `rgb(... / rgb(... / rgb(...)))` therefore creates recursive parser calls while never accumulating depth toward the `> 500` limit. This permits unbounded recursion until process stack exhaustion.

## Why This Is A Real Bug

The parser explicitly implements a maximum nesting depth defense in `TokenList::parse_into`, but one recognized recursive path failed to propagate the current depth. Because `rgb()`/`hsl()` unresolved alpha parsing re-entered `TokenList::parse` with depth `0`, attacker input could bypass the only relevant recursion guard. The reproduced call chain confirms the bypass and the resulting denial-of-service condition.

## Fix Requirement

Propagate the caller's current nesting depth into `UnresolvedColor::parse`, and parse unresolved `rgb()`/`hsl()` alpha token lists with `depth + 1` instead of `0`.

## Patch Rationale

The patch changes the unresolved color parser API to accept `depth` from `TokenList::parse_into`:

```rust
UnresolvedColor::parse(i, f, options, depth)
```

It then parses slash alpha token lists with:

```rust
TokenListFns::parse(i, options, depth + 1)
```

for both `rgb()` and `hsl()`.

This preserves the existing parser behavior while ensuring unresolved color alpha recursion contributes to the same nesting counter as all other nested token-list parsing paths.

## Residual Risk

None

## Patch

```diff
diff --git a/src/css/properties/custom.rs b/src/css/properties/custom.rs
index 40b7a5b4d3..576c6e3d32 100644
--- a/src/css/properties/custom.rs
+++ b/src/css/properties/custom.rs
@@ -591,7 +591,7 @@ impl TokenList {
                         last_is_delim = false;
                         last_is_whitespace = false;
                     } else if let Ok(color) =
-                        input.try_parse(|i| UnresolvedColor::parse(i, f, options))
+                        input.try_parse(|i| UnresolvedColor::parse(i, f, options, depth))
                     {
                         tokens.push(TokenOrValue::UnresolvedColor(color));
                         last_is_delim = false;
@@ -956,7 +956,12 @@ impl UnresolvedColor {
         }
     }
 
-    pub fn parse(input: &mut Parser, f: &[u8], options: &ParserOptions) -> Result<UnresolvedColor> {
+    pub fn parse(
+        input: &mut Parser,
+        f: &[u8],
+        options: &ParserOptions,
+        depth: usize,
+    ) -> Result<UnresolvedColor> {
         use css_values::color::{
             ComponentParser, HSL, SRGB, parse_hsl_hwb_components, parse_rgb_components,
         };
@@ -970,7 +975,7 @@ impl UnresolvedColor {
                         return Err(i.new_custom_error(ParserError::invalid_value));
                     }
                     i.expect_delim(b'/')?;
-                    let alpha = TokenListFns::parse(i, options, 0)?;
+                    let alpha = TokenListFns::parse(i, options, depth + 1)?;
                     Ok(UnresolvedColor::RGB { r, g, b, alpha })
                 })
             });
@@ -982,7 +987,7 @@ impl UnresolvedColor {
                         return Err(i.new_custom_error(ParserError::invalid_value));
                     }
                     i.expect_delim(b'/')?;
-                    let alpha = TokenListFns::parse(i, options, 0)?;
+                    let alpha = TokenListFns::parse(i, options, depth + 1)?;
                     Ok(UnresolvedColor::HSL { h, s, l, alpha })
                 })
             });
```