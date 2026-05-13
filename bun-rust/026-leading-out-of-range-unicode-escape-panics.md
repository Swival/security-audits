# Leading Out-Of-Range Unicode Escape Panics

## Classification

Denial of service, medium severity.

## Affected Locations

`src/js_parser/lexer.rs:719`

## Summary

A JavaScript source file that starts with a string containing an out-of-range variable-length Unicode escape, such as `"\u{110000}"`, can panic the lexer instead of producing a syntax error. In deployments that parse untrusted JavaScript, this lets a remote input abort parsing and, with `panic = "abort"`, terminate the process.

## Provenance

Verified finding from Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The service parses untrusted JavaScript source with this lexer.
- The attacker can supply source beginning with a string literal containing a variable-length Unicode escape.
- Workspace panic settings use `panic = "abort"`, so parser panics abort the process.

## Proof

The reproduced path is:

- Expression parsing calls `parse_string_literal()` in `src/js_parser/parse/mod.rs:326`.
- `parse_string_literal()` immediately calls `p.lexer.to_e_string()` in `src/js_parser/parse/mod.rs:329`.
- `to_e_string()` calls `decode_escape_sequences(self.string_literal_start, self.string_literal_raw_content, ...)` in `src/js_parser/lexer.rs:2811`.
- For a leading escape such as `"\u{110000}"`, `start = 0` and the cursor reaches the `{` with `iter.i = 2`.
- The vulnerable calculation computes `hex_start = (iter.i + start) - width - width2 - width3`.
- With a leading escape this becomes `0 - 1`, causing unsigned `usize` underflow before the out-of-range escape can be reported.
- In checked builds this panics on arithmetic overflow; in release it can wrap and later panic at `.unwrap()` while constructing the diagnostic range.
- Because `Cargo.toml:152` and `Cargo.toml:155` configure `panic = "abort"`, the panic aborts the process.

## Why This Is A Real Bug

The lexer already detects out-of-range Unicode escapes and intends to report `"Unicode escape sequence is out of range"` through `add_range_error()`. The panic occurs while calculating the diagnostic location, before normal error handling can return `Error::SyntaxError`.

The input is attacker-controlled JavaScript source, requires no invalid memory access or local privileges, and triggers during ordinary string literal parsing. With abort-on-panic profiles, this is a process-level denial of service.

## Fix Requirement

Compute the variable-length Unicode escape diagnostic offset relative to the raw string text, not by subtracting escape widths from an absolute `start + iter.i` value. The calculation must use checked or saturating arithmetic so a leading escape cannot underflow.

## Patch Rationale

The patch changes `hex_start` to be calculated from `iter.i` alone using `saturating_sub()` for each width component:

```rust
let hex_start = (iter.i as usize)
    .saturating_sub(width as usize)
    .saturating_sub(width2 as usize)
    .saturating_sub(width3 as usize);
```

This makes `hex_start` a text-relative offset and prevents unsigned underflow for leading escapes. The diagnostic length calculation is also changed to:

```rust
(iter.i as usize).saturating_sub(hex_start)
```

This keeps range construction consistent with the new text-relative offset and prevents a second underflow path.

## Residual Risk

None

## Patch

```diff
diff --git a/src/js_parser/lexer.rs b/src/js_parser/lexer.rs
index c08c2c3471..d0812e3304 100644
--- a/src/js_parser/lexer.rs
+++ b/src/js_parser/lexer.rs
@@ -874,10 +874,10 @@ lexer_impl_header! {
                                     self.syntax_error()?;
                                 }
 
-                                let hex_start = (iter.i as usize + start)
-                                    - width as usize
-                                    - width2 as usize
-                                    - width3 as usize;
+                                let hex_start = (iter.i as usize)
+                                    .saturating_sub(width as usize)
+                                    .saturating_sub(width2 as usize)
+                                    .saturating_sub(width3 as usize);
                                 let mut is_first = true;
                                 let mut is_out_of_range = false;
                                 'variable_length: loop {
@@ -930,7 +930,7 @@ lexer_impl_header! {
                                                     .unwrap(),
                                             },
                                             len: i32::try_from(
-                                                (iter.i as usize + start) - hex_start,
+                                                (iter.i as usize).saturating_sub(hex_start),
                                             )
                                             .unwrap(),
                                         },
```