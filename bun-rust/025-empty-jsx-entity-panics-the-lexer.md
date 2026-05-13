# Empty JSX Entity Panics Lexer

## Classification

Denial of service, medium severity, confirmed.

## Affected Locations

`src/js_parser/lexer.rs:3385`

## Summary

An empty JSX entity sequence `&;` reaches `maybe_decode_jsx_entity()`, which slices an empty entity and then reads `entity[0]`. Rust bounds checks panic on this zero-length slice. In builds configured with `panic = "abort"`, this can abort the process and deny service to clients relying on JSX parsing.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- A service parses attacker-controlled JSX.
- JSX parsing is enabled.
- Rust bounds checks are active.
- The service is run with panic behavior that can terminate parsing or abort the process.

## Proof

- Attacker input can include JSX child text or JSX string content containing `&;`, for example a JSX attribute value such as `title="&;"`.
- JSX child text reaches `expect_jsx_element_child()` / `next_jsx_element_child()` in `src/js_parser/parse/parse_jsx.rs:286`, then `src/js_parser/lexer.rs:3210`.
- `&` marks the text as needing entity decoding at `src/js_parser/lexer.rs:3240`.
- Decoding flows through `fix_whitespace_and_decode_jsx_entities()` at `src/js_parser/lexer.rs:3264`, then `decode_jsx_entities()` at `src/js_parser/lexer.rs:3355`.
- `maybe_decode_jsx_entity()` finds `;` immediately after `&`, computes `entity = &text[end..end + length]` with `length == 0`, then reads `entity[0]`, causing a bounds-check panic.
- Committed profiles set `panic = "abort"` in `Cargo.toml:153` and `Cargo.toml:155`, so the panic can abort the process in normal dev/release builds.

## Why This Is A Real Bug

The code assumes that finding a semicolon after `&` implies at least one entity byte exists. That assumption is false for `&;`. The reproducer confirms the exact reachable path from JSX parsing into the faulty empty-slice access. This is not a theoretical crash: the failing operation is a direct Rust slice index on an empty slice.

## Fix Requirement

Reject or ignore empty JSX entities before reading `entity[0]`.

## Patch Rationale

The patch adds an explicit `entity.is_empty()` guard immediately after slicing the entity and before inspecting its first byte. Returning leaves the original `&` unchanged in the decoded output path, matching the existing behavior for unrecognized entities while preventing the panic.

## Residual Risk

None

## Patch

```diff
diff --git a/src/js_parser/lexer.rs b/src/js_parser/lexer.rs
index c08c2c3471..6dbc17f96a 100644
--- a/src/js_parser/lexer.rs
+++ b/src/js_parser/lexer.rs
@@ -3385,6 +3385,9 @@ lexer_impl_header! {
             let length = length as usize;
             let end = cursor.width as usize + cursor.i as usize;
             let entity = &text[end..end + length];
+            if entity.is_empty() {
+                return;
+            }
             if entity[0] == b'#' {
                 let mut number = &entity[1..entity.len()];
                 let mut base: u8 = 10;
```