# byte literal accessor checks wrong kind

## Classification

Logic error, medium severity, confidence certain.

## Affected Locations

`library/proc_macro/src/lib.rs:1439`

## Summary

`Literal::byte_character_value` is documented to return the unescaped value for byte character literals, but it checks for `bridge::LitKind::Char` instead of `bridge::LitKind::Byte`. This rejects valid byte character literals and incorrectly allows character literals to enter byte unescaping.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

A caller invokes `byte_character_value` on a `Literal`.

## Proof

A byte character literal can originate from public constructors or parsing:

- `Literal::byte_character` creates a literal with `bridge::LitKind::Byte`.
- `Literal::from_str("b'A'")` routes through `BridgeMethods::literal_from_str`.
- The compiler bridge maps `token::Byte` to `LitKind::Byte`.

The affected method then matches `bridge::LitKind::Char`, not `bridge::LitKind::Byte`. Therefore:

- A real byte character literal reaches the `_` arm and returns `ConversionErrorKind::InvalidLiteralKind`.
- A character literal created by `Literal::character` has `bridge::LitKind::Char` and is incorrectly passed to `unescape_byte`.

## Why This Is A Real Bug

The public unstable `proc_macro_value` API exposes `byte_character_value` as the accessor for byte character literals. Its implementation contradicts that contract by rejecting the actual internal byte literal kind and accepting the character literal kind. The result is observable incorrect conversion behavior for valid public API inputs.

## Fix Requirement

Match `bridge::LitKind::Byte` in `byte_character_value` instead of `bridge::LitKind::Char`.

## Patch Rationale

The patch changes only the discriminant checked by `byte_character_value`. This aligns the accessor with:

- The method documentation.
- `Literal::byte_character`, which constructs `bridge::LitKind::Byte`.
- The compiler bridge behavior for parsed byte literals.
- The existing use of `unescape_byte`, which is appropriate for byte character literal contents.

## Residual Risk

None

## Patch

```diff
diff --git a/library/proc_macro/src/lib.rs b/library/proc_macro/src/lib.rs
index a01bf38a62d..fcc14a452e0 100644
--- a/library/proc_macro/src/lib.rs
+++ b/library/proc_macro/src/lib.rs
@@ -1461,7 +1461,7 @@ fn get_hashes_str(num: u8) -> &'static str {
     #[unstable(feature = "proc_macro_value", issue = "136652")]
     pub fn byte_character_value(&self) -> Result<u8, ConversionErrorKind> {
         self.0.symbol.with(|symbol| match self.0.kind {
-            bridge::LitKind::Char => {
+            bridge::LitKind::Byte => {
                 unescape_byte(symbol).map_err(ConversionErrorKind::FailedToUnescape)
             }
             _ => Err(ConversionErrorKind::InvalidLiteralKind),
```