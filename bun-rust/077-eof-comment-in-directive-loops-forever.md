# EOF comment in directive loops forever

## Classification

Denial of service, medium severity, confidence certain.

## Affected Locations

`src/parsers/yaml.rs:5487`

## Summary

A YAML directive comment that reaches EOF without a trailing newline causes the parser to spin forever. The directive parser enters `try_skip_to_new_line`, consumes `#`, and loops until LF or CR. At EOF, `is_char('\n')` and `is_char('\r')` both return false while `inc(1)` clamps `pos` to `input.len()`, so the loop makes no progress.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

The service parses attacker-supplied YAML directives.

## Proof

A leading `%` is scanned as `TokenData::Directive`, then `Parser::parse` reaches `parse_stream`, `parse_document`, and `parse_directive`.

Valid directive paths call `try_skip_to_new_line` after parsing directive content:

- YAML directive sink: `src/parsers/yaml.rs:2445`
- TAG directive sinks: `src/parsers/yaml.rs:2461`, `src/parsers/yaml.rs:2473`, `src/parsers/yaml.rs:2492`, `src/parsers/yaml.rs:2511`
- Reserved directive sink: `src/parsers/yaml.rs:2531`

In `try_skip_to_new_line`, the parser consumes `#` and then executes:

```rust
while !self.is_char(Enc::ch(b'\n')) && !self.is_char(Enc::ch(b'\r')) {
    self.inc(1);
}
```

At EOF, `is_char` returns false because `pos` is not less than `input.len()`, and `inc` clamps `pos` to `input.len()`. For a directive comment ending at EOF without LF or CR, the condition remains true forever.

## Why This Is A Real Bug

The loop condition excludes EOF even though EOF is a valid terminator for `s-l-comments`. The parser already has `is_b_char_or_eof`, and other comment-scanning code uses it to terminate on either a line break or EOF. Because `inc` cannot advance past EOF, this is a deterministic infinite loop, not a slow parse or theoretical edge case.

## Fix Requirement

Stop the directive-comment loop when EOF is reached. The loop must terminate on either a YAML break character or EOF.

## Patch Rationale

Replacing the LF/CR-only condition with `!self.is_b_char_or_eof()` preserves the existing behavior for newline-terminated comments and adds the missing EOF termination. This matches the helper’s semantics and avoids manual bounds checks.

## Residual Risk

None

## Patch

```diff
diff --git a/src/parsers/yaml.rs b/src/parsers/yaml.rs
index 06adb0292b..61337316a8 100644
--- a/src/parsers/yaml.rs
+++ b/src/parsers/yaml.rs
@@ -5484,7 +5484,7 @@ impl<'i, Enc: Encoding> Parser<'i, Enc> {
                 return Err(ParseError::UnexpectedCharacter);
             }
             self.inc(1);
-            while !self.is_char(Enc::ch(b'\n')) && !self.is_char(Enc::ch(b'\r')) {
+            while !self.is_b_char_or_eof() {
                 self.inc(1);
             }
         }
```