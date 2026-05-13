# Multibyte EOF Codepoint Overreads Source Buffer

## Classification

Out-of-bounds read, high severity.

Confidence: certain.

## Affected Locations

- `src/parsers/toml/lexer.rs:235`

## Summary

The TOML lexer unsafely converts a 2- or 3-byte UTF-8 slice at EOF into a `&[u8; 4]`. When attacker-controlled TOML ends with a valid multibyte codepoint, the lexer accepts the slice as in-bounds, then creates a four-byte reference that extends past `source.contents`. This is undefined behavior and can read beyond the TOML source buffer during lexing.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The parser lexes attacker-controlled TOML.
- The TOML source ends with a valid two- or three-byte UTF-8 codepoint.

## Proof

`Source::init_path_string` accepts attacker-controlled bytes at `src/runtime/api.rs:283`. `TOML::parse` initializes the TOML lexer at `src/parsers/toml.rs:291`. `Lexer::init` immediately calls `lex.step()` at `src/parsers/toml/lexer.rs:1402`.

During `step()`, `next_codepoint()` computes `cp_len` from the leading byte at `src/parsers/toml/lexer.rs:220`. If exactly `cp_len` bytes remain, the bounds check at `src/parsers/toml/lexer.rs:223` accepts `source.contents[current..current + cp_len]`.

For a 2- or 3-byte codepoint at EOF, `slice.len()` is `2` or `3`. The `_` match arm then executes:

```rust
unsafe { &*slice.as_ptr().cast::<[u8; 4]>() }
```

at `src/parsers/toml/lexer.rs:235`.

That creates a `&[u8; 4]` even though only 2 or 3 bytes remain in `source.contents`.

## Why This Is A Real Bug

The comment claimed that `contents` has at least four bytes available when `cp_len > 1`, but the preceding bounds check only proves that `cp_len` bytes are available. At EOF, a valid 2- or 3-byte codepoint satisfies that check while still leaving fewer than four bytes.

Creating `&[u8; 4]` from a pointer to a shorter slice violates Rust reference validity requirements and is undefined behavior before or during `decode_wtf8_rune_t_multibyte`.

Comparable lexer implementations avoid this pattern by copying into a zero-padded `[u8; 4]` stack buffer before decoding at `src/parsers/json_lexer.rs:394` and `src/js_parser/lexer.rs:1305`.

## Fix Requirement

Multibyte decoding must receive a valid four-byte buffer without reading beyond `source.contents`. For slices shorter than four bytes, the lexer must copy the available bytes into a local zero-padded `[u8; 4]` and pass a reference to that local buffer.

## Patch Rationale

The patch removes the unsafe cast and replaces it with a stack-allocated `[u8; 4]`. It copies exactly `slice.len()` bytes into the start of the buffer and leaves the remaining bytes zeroed. The decoder still receives the actual codepoint length via the existing `slice.len()` argument, preserving decoding behavior while ensuring the referenced object is truly four bytes long.

## Residual Risk

None

## Patch

```diff
diff --git a/src/parsers/toml/lexer.rs b/src/parsers/toml/lexer.rs
index ed47e9acec..d99c379395 100644
--- a/src/parsers/toml/lexer.rs
+++ b/src/parsers/toml/lexer.rs
@@ -229,14 +229,15 @@ impl<'a> Lexer<'a> {
         let code_point: CodePoint = match slice.len() {
             0 => -1,
             1 => slice[0] as CodePoint,
-            _ => strings::decode_wtf8_rune_t_multibyte(
-                // SAFETY: contents has at least 4 bytes available from `current` when cp_len > 1
-                // (matches Zig `slice.ptr[0..4]` which over-reads up to 4 bytes).
-                // TODO(port): verify bun_str signature; may take &[u8; 4] or *const u8.
-                unsafe { &*slice.as_ptr().cast::<[u8; 4]>() },
-                u8::try_from(slice.len()).expect("int cast"), // @intCast to u3
-                strings::UNICODE_REPLACEMENT as CodePoint,
-            ),
+            _ => {
+                let mut bytes = [0; 4];
+                bytes[..slice.len()].copy_from_slice(slice);
+                strings::decode_wtf8_rune_t_multibyte(
+                    &bytes,
+                    u8::try_from(slice.len()).expect("int cast"), // @intCast to u3
+                    strings::UNICODE_REPLACEMENT as CodePoint,
+                )
+            }
         };
 
         self.end = self.current;
```