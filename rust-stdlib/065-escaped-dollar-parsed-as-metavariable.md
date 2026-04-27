# Escaped Dollar Parsed As Metavariable

## Classification

Logic error, low severity, certain confidence.

## Affected Locations

`library/proc_macro/src/quote.rs:462`

## Summary

`quote!` repetition metavariable collection incorrectly treats an escaped dollar sequence followed by an identifier, `$$ident`, as if it contained the metavariable `$ident`.

This violates the documented `$$` escape behavior for quoting a literal dollar and can cause generated repetition setup code to reference or iterate an unintended local identifier.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A `quote!` repetition contains an escaped dollar followed by an identifier, for example:

```rust
quote! { $($x $$var)* }
```

## Proof

Repetition contents come from the `TokenTree::Group` following `$` in `quote()`.

Before generating repetition code, `quote()` calls:

```rust
let meta_vars = collect_meta_vars(contents.clone());
```

`collect_meta_vars` scans the repetition contents and treats every `$` punct followed by an `Ident` as a metavariable. For `$$var`, the first `$` sees another `$`, but the second `$` then sees `Ident(var)` and records `var`.

Every collected metavariable is then emitted into repetition setup code:

```rust
let (mut var, i) = var.quote_into_iter();
```

and later advanced inside the repetition loop.

As a result, a literal escaped `$var` inside a repetition is not purely literal: it causes unintended generated code to bind and iterate `var`.

## Why This Is A Real Bug

`$$` is documented as the way to quote a literal dollar in `library/proc_macro/src/lib.rs:458`.

The recursive quote path correctly emits `$$var` as a literal `$` followed by `var`. The bug is isolated to the repetition metavariable collector, which misclassifies the escaped sequence before recursive quoting occurs.

Practical effects:

- `quote! { $($x $$var)* }` fails to compile if no local `var` exists.
- If an unrelated local `var` exists, generated repetition code may silently bind and iterate it.
- This behavior contradicts the escape invariant for `$$`.

## Fix Requirement

`collect_meta_vars` must recognize escaped `$$` and skip the second dollar before checking for `$ident` metavariables.

## Patch Rationale

The patch changes the `$` handling branch in `collect_meta_vars` from a single `peek()` check for `Ident` to a match that handles escaped dollars first.

When the collector sees `$` followed by another `$`, it consumes the second `$` and records no metavariable. This preserves the documented literal-dollar behavior and prevents the second `$` in `$$ident` from being reinterpreted as the start of `$ident`.

Normal metavariable collection remains unchanged for `$ident`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/proc_macro/src/quote.rs b/library/proc_macro/src/quote.rs
index dbb55cd9fb3..198b71ec5c3 100644
--- a/library/proc_macro/src/quote.rs
+++ b/library/proc_macro/src/quote.rs
@@ -459,9 +459,15 @@ fn helper(stream: TokenStream, out: &mut Vec<Ident>) {
         while let Some(tree) = iter.next() {
             match &tree {
                 TokenTree::Punct(tt) if tt.as_char() == '$' => {
-                    if let Some(TokenTree::Ident(id)) = iter.peek() {
-                        out.push(id.clone());
-                        iter.next();
+                    match iter.peek() {
+                        Some(TokenTree::Punct(tt)) if tt.as_char() == '$' => {
+                            iter.next();
+                        }
+                        Some(TokenTree::Ident(id)) => {
+                            out.push(id.clone());
+                            iter.next();
+                        }
+                        _ => {}
                     }
                 }
                 TokenTree::Group(tt) => {
```