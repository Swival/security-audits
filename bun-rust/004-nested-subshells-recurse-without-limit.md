# Nested Subshells Recurse Without Limit

## Classification

Denial of service, medium severity.

## Affected Locations

`src/shell_parser/parse.rs:3549`

## Summary

The shell lexer recursively invokes `lex()` for every nested subshell or command substitution without tracking nesting depth. Attacker-controlled shell source containing deeply nested `(` or `$(` sequences can force linear recursive stack growth until the lexer thread exhausts stack and denies service.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

Application lexes attacker-controlled shell source bytes.

## Proof

`Lexer::lex` handles command substitutions by calling `eat_subshell(SubShellKind::Dollar)` for `$(` and normal subshells by calling `eat_subshell(SubShellKind::Normal)` for `(`.

`eat_subshell` pushes the corresponding subshell token, constructs a sublexer via `make_sublexer`, then directly calls `sublexer.lex()?` before returning.

Balanced inputs such as:

```text
"(".repeat(N) + ")".repeat(N)
```

or:

```text
"$(".repeat(N) + ")".repeat(N)
```

with `$(` repeated as the opening sequence create `N` nested `lex()` calls before unwinding. Unclosed variants also recurse to attacker-controlled depth before reporting a lex error.

The original lexer had no depth argument, counter, or guard in `Lexer`, `make_sublexer`, or `eat_subshell`; `in_subshell: Option<SubShellKind>` only tracked the current delimiter kind.

## Why This Is A Real Bug

The recursion depth is directly controlled by input bytes. Each nested subshell creates another Rust call stack frame through `eat_subshell -> sublexer.lex()`. With sufficiently large nesting, stack consumption grows linearly until stack exhaustion, terminating or panicking the parser thread and causing denial of service.

## Fix Requirement

Track subshell nesting depth across sublexers and reject inputs exceeding a bounded maximum before making another recursive `lex()` call.

## Patch Rationale

The patch adds `MAX_SUBSHELL_DEPTH: u32 = 128`, a `subshell_depth` field on `Lexer`, initializes it to `0`, increments it when constructing a sublexer, and checks the limit in `eat_subshell` before recursion.

When the limit is exceeded, the lexer records `Subshell nesting depth exceeded` and returns `LexerError::SubshellDepthExceeded`, preventing unbounded stack growth while preserving normal parsing for reasonable nesting.

## Residual Risk

None

## Patch

```diff
diff --git a/src/shell_parser/parse.rs b/src/shell_parser/parse.rs
index 6fc9740b42..afe48fafc3 100644
--- a/src/shell_parser/parse.rs
+++ b/src/shell_parser/parse.rs
@@ -2409,6 +2409,7 @@ pub struct LexError {
 /// \b (decimal value of 8) is deliberately chosen so that it is not
 /// easy for the user to accidentally use this char in their script.
 const SPECIAL_JS_CHAR: u8 = 8;
+const MAX_SUBSHELL_DEPTH: u32 = 128;
 pub const LEX_JS_OBJREF_PREFIX: &[u8] = b"\x08__bun_";
 pub const LEX_JS_STRING_PREFIX: &[u8] = b"\x08__bunstr_";
 
@@ -2429,6 +2430,8 @@ pub enum LexerError {
     Utf8InvalidStartByte,
     #[error("CodepointTooLarge")]
     CodepointTooLarge,
+    #[error("Subshell nesting depth exceeded")]
+    SubshellDepthExceeded,
 }
 
 #[derive(Clone, Copy, PartialEq, Eq)]
@@ -2470,6 +2473,7 @@ pub struct Lexer<'bump, const ENCODING: StringEncoding> {
     pub tokens: bun_alloc::ArenaVec<'bump, Token>,
     pub delimit_quote: bool,
     pub in_subshell: Option<SubShellKind>,
+    pub subshell_depth: u32,
     pub errors: bun_alloc::ArenaVec<'bump, LexError>,
 
     /// Contains a list of strings we need to escape
@@ -2498,6 +2502,7 @@ impl<'bump, const ENCODING: StringEncoding> Lexer<'bump, ENCODING> {
             j: 0,
             delimit_quote: false,
             in_subshell: None,
+            subshell_depth: 0,
             string_refs: strings_to_escape,
             jsobjs_len,
         }
@@ -2535,6 +2540,7 @@ impl<'bump, const ENCODING: StringEncoding> Lexer<'bump, ENCODING> {
             tokens: core::mem::replace(&mut self.tokens, bun_alloc::ArenaVec::new_in(bump)),
             errors: core::mem::replace(&mut self.errors, bun_alloc::ArenaVec::new_in(bump)),
             in_subshell: Some(kind),
+            subshell_depth: self.subshell_depth + 1,
             word_start: self.word_start,
             j: self.j,
             delimit_quote: false,
@@ -3547,6 +3553,11 @@ impl<'bump, const ENCODING: StringEncoding> Lexer<'bump, ENCODING> {
     }
 
     fn eat_subshell(&mut self, kind: SubShellKind) -> Result<(), LexerError> {
+        if self.subshell_depth >= MAX_SUBSHELL_DEPTH {
+            self.add_error(b"Subshell nesting depth exceeded");
+            return Err(LexerError::SubshellDepthExceeded);
+        }
+
         if kind == SubShellKind::Dollar {
             // Eat the open paren
             let _ = self.eat();
```