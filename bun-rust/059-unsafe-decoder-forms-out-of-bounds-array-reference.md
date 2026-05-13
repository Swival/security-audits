# Unsafe Decoder Forms Out-of-Bounds Array Reference

## Classification

High severity memory corruption / Rust memory-safety violation.

Confidence: certain.

## Affected Locations

`src/parsers/json5.rs:819`

## Summary

`JSON5Parser::read_codepoint()` validated only that the current UTF-8/WTF-8 sequence length fit in the input, then created a `&[u8; 4]` reference at `self.pos`. For valid 2- or 3-byte non-ASCII sequences ending at EOF, fewer than four bytes remain, so the reference itself extends past the input slice.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched from source evidence.

## Preconditions

- The service parses attacker-controlled JSON5 input.
- The attacker supplies a JSON5 document where a non-ASCII identifier-start byte sequence begins within the final three bytes of the input.

## Proof

`scan()` reaches `read_codepoint()` when tokenizing a non-whitespace byte `>= 0x80` as a possible identifier start.

`read_codepoint()` checks:

```rust
if self.pos + usize::from(seq_len) > self.source.len() {
    return Some(Codepoint {
        cp: i32::from(first),
        len: 1,
    });
}
```

For a complete 2-byte or 3-byte sequence at EOF, this check passes. The old code then formed:

```rust
&*self.source.as_ptr().add(self.pos).cast::<[u8; 4]>()
```

This creates a Rust reference to four bytes starting at `self.pos`, even when only two or three bytes remain in `self.source`.

A concrete trigger is a JSON5 input containing only bytes `C3 80`, representing `U+00C0`, a valid non-ASCII identifier-start character at EOF. `scan()` calls `read_codepoint()`, `seq_len == 2`, and the unsafe `&[u8; 4]` reference extends two bytes past the input slice.

The parser is reachable from attacker-controlled input through `Bun.JSON5.parse` in `src/runtime/api/JSON5Object.rs:49`, which accepts string/blob/buffer input through `with_text_format_source` in `src/runtime/api.rs:266`.

## Why This Is A Real Bug

Rust references must be valid for the full referenced object. Creating `&[u8; 4]` out of a slice with fewer than four remaining bytes is undefined behavior, regardless of whether the decoder later reads only `seq_len` bytes.

The bounds check proved only `seq_len` bytes were available. It did not prove four bytes were available.

## Fix Requirement

Decode from a local four-byte buffer that is always valid, copying only the available `seq_len` bytes from the input and leaving the remaining bytes padded.

## Patch Rationale

The patch removes the unsafe pointer cast and replaces it with a stack-allocated `[u8; 4]`:

```rust
let seq_len_usize = usize::from(seq_len);
let mut bytes = [0u8; 4];
bytes[..seq_len_usize]
    .copy_from_slice(&self.source[self.pos..self.pos + seq_len_usize]);
let decoded = strings::decode_wtf8_rune_t(&bytes, seq_len, -1i32);
```

This preserves decoder behavior for the valid sequence bytes while ensuring the `&[u8; 4]` reference always points to a real four-byte object.

## Residual Risk

None

## Patch

```diff
diff --git a/src/parsers/json5.rs b/src/parsers/json5.rs
index a6853b6890..8d05b36b5d 100644
--- a/src/parsers/json5.rs
+++ b/src/parsers/json5.rs
@@ -1097,17 +1097,11 @@ impl<'a> JSON5Parser<'a> {
                 len: 1,
             });
         }
-        // SAFETY: Zig reinterprets the slice ptr as *const [4]u8; we have at least
-        // seq_len (≤4) valid bytes at self.pos. decode_wtf8_rune_t reads at most seq_len bytes.
-        // TODO(port): verify decode_wtf8_rune_t signature — Zig passes ptr[0..4] which may
-        // read past end-of-buffer when seq_len < 4 and remaining < 4; preserve that contract.
-        let decoded = unsafe {
-            strings::decode_wtf8_rune_t(
-                &*self.source.as_ptr().add(self.pos).cast::<[u8; 4]>(),
-                seq_len,
-                -1i32,
-            )
-        };
+        let seq_len_usize = usize::from(seq_len);
+        let mut bytes = [0u8; 4];
+        bytes[..seq_len_usize]
+            .copy_from_slice(&self.source[self.pos..self.pos + seq_len_usize]);
+        let decoded = strings::decode_wtf8_rune_t(&bytes, seq_len, -1i32);
         if decoded < 0 {
             return Some(Codepoint {
                 cp: i32::from(first),
```