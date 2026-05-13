# unsafe WTF-8 decoder forms out-of-bounds array reference

## Classification

High severity out-of-bounds read.

Confidence: certain.

## Affected Locations

`src/glob/matcher.rs:566`

## Summary

`decode_wtf8_rune_at` formed an unsafe `&[u8; 4]` reference from `bytes.as_ptr().add(idx)` without proving that four bytes remained in the slice. Bracket glob matching calls this decoder when `path_index < path.len()`, so a path ending in a 1-3 byte suffix can cause the function to create an out-of-bounds array reference before WTF-8 decoding occurs.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- Caller matches attacker-controlled filesystem path bytes against a bracket glob.
- The bracket glob reaches a path suffix with fewer than four remaining bytes.
- The suffix begins with a byte whose WTF-8 sequence length may be interpreted as multi-byte, such as `0xF0`.

## Proof

In `glob_match_impl`, the `[` arm calls:

```rust
let (c, len) = decode_wtf8_rune_at(path, state.path_index as usize);
```

This call is guarded only by `state.path_index < path.len()`.

The vulnerable decoder computed the sequence length from `bytes[idx]`, then created:

```rust
unsafe { &*bytes.as_ptr().add(idx).cast::<[u8; 4]>() }
```

No check established `idx + 4 <= bytes.len()`.

A reproduced ASan harness using the committed decoder logic with path bytes `[0xF0]` and a bracket glob reported a `heap-buffer-overflow` on the first read past the one-byte allocation.

Reachability is practical on POSIX because directory entry names are raw bytes from `getdents64` and are exposed through `entry.name.slice_u8()`. `GlobWalker` passes attacker-controlled entry names into `crate::r#match(...)` for slow glob components at `src/glob/GlobWalker.rs:1855`.

## Why This Is A Real Bug

Rust references must be valid for the full referenced object. Creating `&[u8; 4]` at `bytes[idx]` is invalid when fewer than four bytes remain, even if the callee is expected to use only `len` bytes. Therefore the unsafe cast can read past the path buffer and violates Rust memory-safety requirements.

A lower-privileged local user can create attacker-controlled filenames, including invalid or truncated byte sequences such as a single `0xF0` byte, and trigger the bracket glob matcher against those names.

## Fix Requirement

The decoder must not form a four-byte reference into the original slice unless four bytes are available. It must provide `decode_wtf8_rune_t` with a valid four-byte buffer for all in-bounds `idx` values.

## Patch Rationale

The patch replaces the unsafe array-reference cast with a local zero-padded `[u8; 4]` buffer:

```rust
let mut buf = [0; 4];
let available = (bytes.len() - idx).min(4);
buf[..available].copy_from_slice(&bytes[idx..idx + available]);
let cp = strings::decode_wtf8_rune_t::<u32>(&buf, len, 0xFFFD);
```

This preserves the decoder interface while ensuring the referenced array is always fully valid. Available bytes are copied from the input, and missing trailing bytes are zero-filled before decoding.

## Residual Risk

None

## Patch

```diff
diff --git a/src/glob/matcher.rs b/src/glob/matcher.rs
index 6ea327a8b8..671c5efc99 100644
--- a/src/glob/matcher.rs
+++ b/src/glob/matcher.rs
@@ -563,18 +563,14 @@ fn unescape(c: &mut u8, glob: &[u8], glob_index: &mut u32) -> bool {
 
 /// Decodes the WTF-8 codepoint at `bytes[idx]`, returning `(codepoint, byte_len)`.
 ///
-/// Mirrors the open-coded triple in matcher.zig (`wtf8ByteSequenceLength` + `decodeWTF8RuneT`
-/// over `bytes[idx..].ptr[0..4]`). Centralized so the `[u8; 4]` reinterpret has a single
-/// audit point.
+/// Mirrors the open-coded triple in matcher.zig (`wtf8ByteSequenceLength` + `decodeWTF8RuneT`).
 #[inline(always)]
 fn decode_wtf8_rune_at(bytes: &[u8], idx: usize) -> (u32, u8) {
     let len = strings::wtf8_byte_sequence_length(bytes[idx]);
-    // SAFETY: matches Zig `bytes[idx..].ptr[0..4]` — decode reads only `len` bytes
-    let cp = strings::decode_wtf8_rune_t::<u32>(
-        unsafe { &*bytes.as_ptr().add(idx).cast::<[u8; 4]>() },
-        len,
-        0xFFFD,
-    );
+    let mut buf = [0; 4];
+    let available = (bytes.len() - idx).min(4);
+    buf[..available].copy_from_slice(&bytes[idx..idx + available]);
+    let cp = strings::decode_wtf8_rune_t::<u32>(&buf, len, 0xFFFD);
     (cp, len)
 }
```