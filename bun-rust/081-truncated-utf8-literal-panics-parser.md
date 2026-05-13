# Truncated UTF-8 Literal Panics Parser

## Classification

Denial of service, medium severity, certain confidence.

## Affected Locations

`src/css/values/syntax.rs:352`

## Summary

A CSS custom property syntax literal ending in a truncated multibyte UTF-8 lead byte can panic the parser. The literal scanner advances by the expected UTF-8 byte sequence length without checking that enough bytes remain, then slices past the end of the input.

## Provenance

Verified from the provided reproducer and patch. Initially identified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

CSS syntax string bytes can contain invalid or truncated UTF-8.

## Proof

An attacker-controlled CSS file can include an `@property` syntax declaration whose quoted syntax string contains a literal ending with a truncated multibyte byte, such as a lone `0xE2`.

Observed path:

- Raw CSS bytes enter the parser as `&[u8]` without UTF-8 validation at `src/css/css_parser.rs:2827`.
- `@property` parsing reaches `PropertyRule::parse`.
- `syntax` declarations call `SyntaxString::parse(input)?` at `src/css/rules/property.rs:192`.
- Quoted strings preserve invalid or truncated bytes; `consume_quoted_string` advances over non-ASCII bytes without validating the full sequence and returns the raw slice at `src/css/css_parser.rs:5061`.
- `SyntaxComponentKind::parse_string` treats `0xE2` as an identifier/name byte because bytes `>= 0x80` satisfy `is_ident_start` and `is_name_code_point`.
- The loop advances `end_idx` by `utf8_byte_sequence_length(0xE2) == 3` while `input.len() == 1`.
- The subsequent slice `&input[0..end_idx]` exceeds `input.len()` and triggers a Rust bounds-check panic.

Impact: parsing attacker-controlled CSS can abort CSS syntax processing, which is a practical denial of service for tooling that processes untrusted CSS, such as CSS from a malicious package or repository.

## Why This Is A Real Bug

The code accepts byte slices, not validated UTF-8 strings, and the reproducer confirms invalid or truncated bytes can reach `SyntaxComponentKind::parse_string`. The scanner loop assumes a full UTF-8 sequence exists whenever it sees a multibyte lead byte. That assumption is false for the accepted input type and parser behavior. The resulting out-of-bounds slice is a deterministic panic, not merely a rejected parse.

## Fix Requirement

The literal scanner must never advance beyond the remaining input. It must either cap UTF-8 advancement to the remaining input length or reject truncated sequences before slicing.

## Patch Rationale

The patch caps the computed next index to `input.len()`:

```rust
end_idx = (end_idx + (strings::utf8_byte_sequence_length(input[end_idx]).max(1)) as usize).min(input.len());
```

This preserves the existing behavior for valid input, keeps the prior protection against zero-length advancement for invalid lead or continuation bytes, and prevents `end_idx` from exceeding the slice length before `Box::from(&input[0..end_idx])`.

## Residual Risk

None

## Patch

```diff
diff --git a/src/css/values/syntax.rs b/src/css/values/syntax.rs
index cd43216f65..fca2a60c4c 100644
--- a/src/css/values/syntax.rs
+++ b/src/css/values/syntax.rs
@@ -344,7 +344,7 @@ impl SyntaxComponentKind {
                 // Spec uses utf8ByteSequenceLengthUnsafe (unreachable for invalid lead bytes);
                 // clamp to >=1 so a stray 0x80..=0xBF / 0xF8..=0xFF byte advances instead of
                 // returning 0 and spinning forever.
-                end_idx += (strings::utf8_byte_sequence_length(input[end_idx]).max(1)) as usize;
+                end_idx = (end_idx + (strings::utf8_byte_sequence_length(input[end_idx]).max(1)) as usize).min(input.len());
             }
             let literal: Box<[u8]> = Box::from(&input[0..end_idx]);
             *input = &input[end_idx..];
```