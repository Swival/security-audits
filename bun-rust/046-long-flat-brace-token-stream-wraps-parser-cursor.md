# Long Flat Brace Token Stream Wraps Parser Cursor

## Classification

High severity denial of service.

Confidence: certain.

## Affected Locations

`src/shell_parser/braces.rs:827`

`src/shell_parser/braces.rs:637`

`src/shell_parser/braces.rs:1163`

`src/shell_parser/braces.rs:1203`

## Summary

`Bun.$.braces` can build a valid flat brace token stream longer than `u16::MAX`, then pass it to flat brace expansion. The flat expansion table builder stores the token cursor in `u16` while comparing it against `tokens.len()`. When the cursor reaches `65535`, `i += 1` overflows: debug builds panic, and release builds wrap or later abort on checked `u16` conversions. This enables process-level denial of service when attacker-controlled brace input is expanded.

## Provenance

Reported and verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- `Bun.$.braces` is invoked on attacker-controlled brace input.
- The input is a valid flat brace expression.
- Tokenization produces more than `65535` tokens.
- `contains_nested` is false, so expansion takes the flat path through `build_expansion_table_alloc`.

## Proof

A remote client supplies brace patterns to an application that passes them to `Bun.$.braces`.

A valid flat expression with enough comma-separated segments produces at least `65536` tokens. `NewLexer::tokenize` builds an unbounded `Vec<Token>`, and because the input is flat, `contains_nested` remains false. `expand` then calls `build_expansion_table_alloc`, which calls `build_expansion_table`.

In `build_expansion_table`, the scan cursor is declared as:

```rust
let mut i: u16 = 0;
while (i as usize) < tokens.len() {
    ...
    i += 1;
}
```

For `tokens.len() == 65536`, incrementing `i` after `65535` overflows. In debug/dev builds this panics on integer overflow. In release, the cursor wraps to `0`, causing repeated scanning and eventual panic/abort at checked conversions such as `u16::try_from(table.len()).expect("int cast")`.

Workspace profiles use `panic = "abort"` in `Cargo.toml:151` and `Cargo.toml:154`, so the failure can terminate the Bun process.

## Why This Is A Real Bug

The lexer accepts and stores the long token stream before expansion. The flat expansion path assumes token indexes fit in `u16` but does not enforce that invariant before iterating. The loop condition uses `tokens.len()` as an unbounded `usize`, while the cursor is a bounded `u16`, making overflow reachable with a valid input of roughly 64KB. This is externally triggerable when untrusted input reaches `Bun.$.braces`, and the resulting panic or abort is a denial of service.

## Fix Requirement

Before `build_expansion_table` uses `u16` token indexes, it must either:

- reject token streams longer than `u16::MAX`, or
- change all relevant token indexes and expansion table fields to a wider type such as `usize`.

The applied patch implements rejection at the start of `build_expansion_table`.

## Patch Rationale

The expansion table stores token offsets in `u16` through `BraceState` and `ExpansionVariant`. Rejecting `tokens.len() > u16::MAX as usize` preserves the existing representation while enforcing its required bound. Returning `ParserError::UnexpectedToken` converts the malformed-for-this-implementation input into a controlled error instead of allowing cursor overflow, infinite scanning, panic, or process abort.

## Residual Risk

None

## Patch

```diff
diff --git a/src/shell_parser/braces.rs b/src/shell_parser/braces.rs
index 4638744c79..8e3c30579f 100644
--- a/src/shell_parser/braces.rs
+++ b/src/shell_parser/braces.rs
@@ -1158,6 +1158,10 @@ fn build_expansion_table(
         variants: u16,
         prev_tok_end: u16,
     }
+    if tokens.len() > u16::MAX as usize {
+        return Err(ParserError::UnexpectedToken);
+    }
+
     let mut brace_stack: SmallVec<[BraceState; MAX_NESTED_BRACES]> = SmallVec::new();
 
     let mut i: u16 = 0;
```