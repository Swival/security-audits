# AsconHash256 Streaming Update Applies Padding Per Chunk

## Classification

- Type: Cryptographic flaw
- Severity: High
- Confidence: Certain

## Affected Locations

- `lib/std/crypto/ascon.zig:623`
- Affected API: `AsconHash256.update`

## Summary

`AsconHash256.update()` applied Ascon hash padding on every call instead of only during finalization. Because `update()` is public and documented as callable multiple times before `final()`, attacker-controlled chunk boundaries changed the absorbed message and therefore changed the digest for the same logical byte string.

The implementation also lacked a pending partial-block buffer, so partial chunks were XORed into the current rate word immediately. This allowed trivial streaming collisions for different logical messages under different chunking.

## Provenance

- Source: Swival.dev Security Scanner
- URL: https://swival.dev
- Finding: `streaming hash pads every update call`
- Reproduction: Verified

## Preconditions

- An application hashes attacker-controlled streaming chunks with `AsconHash256`.
- The application may call `update()` more than once for one logical message.

## Proof

The original `AsconHash256.update()` processed full 8-byte blocks, then always absorbed padding:

- For a partial chunk, it copied remaining bytes into `padded`, set `padded[remaining] = 0x01`, and absorbed it.
- For an exact-block chunk, it absorbed a separate padding block with `padded[0] = 0x01`.
- `final()` only permuted and extracted output; it did not own padding.
- No partial-block buffer existed.

Verified digest divergence for the same logical byte string:

- `init(); update("Hello, World!"); final()` produced:

```text
f40e1ce8d4272e628e9535193f196f4ff2a720b00f6380c5d6f16b975f3a7777
```

- `init(); update("Hello, "); update("World!"); final()` produced:

```text
42b51b561ddbfd0d941c3c57647632b14ffc0106194b53d11efae46ec03dd7f3
```

These are different digests for the same logical message.

Verified streaming collision:

- `update("A"); update("B")`
- `update("@"); update("C")`

Both produced:

```text
74230844926cb943951af83596f8450eda360a7958b37823df8f74bcd89eb592
```

## Why This Is A Real Bug

A cryptographic hash streaming API must be chunking-invariant: hashing a byte string in one `update()` call must match hashing the same byte string split across multiple `update()` calls.

The existing implementation violated that invariant. Since callers can pass attacker-controlled chunks and no code path prevents multiple `update()` calls, an attacker can influence digest computation through chunk boundaries. The reproduced collision demonstrates a direct security failure beyond test-vector mismatch.

## Fix Requirement

- Buffer partial blocks in `AsconHash256.update()`.
- Process only complete `block_length` blocks in `update()`.
- Apply the single final padding block only in `AsconHash256.final()`.
- Preserve one-shot hashing behavior through `hash()`, which calls `update()` then `final()`.

## Patch Rationale

The patch adds `buf` and `buf_len` to `AsconHash256`, matching the buffering pattern already used by `AsconXof128` and `AsconCxof128`.

`update()` now:

1. Completes any pending buffered partial block.
2. Absorbs and permutes full 8-byte blocks.
3. Stores any remaining bytes without padding.

`final()` now:

1. Builds one padded final block from the buffered remainder.
2. Absorbs it.
3. Performs the final permutation and digest extraction.

This makes padding independent of streaming chunk boundaries.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/crypto/ascon.zig b/lib/std/crypto/ascon.zig
index 3142bc0a89..a8f5851c89 100644
--- a/lib/std/crypto/ascon.zig
+++ b/lib/std/crypto/ascon.zig
@@ -589,6 +589,8 @@ pub const AsconHash256 = struct {
     pub const block_length = 8;
 
     st: AsconState,
+    buf: [block_length]u8,
+    buf_len: usize,
 
     pub const Options = struct {};
 
@@ -606,7 +608,7 @@ pub const AsconHash256 = struct {
         const words: [5]u64 = .{ iv, 0, 0, 0, 0 };
         var st = AsconState.initFromWords(words);
         st.permuteR(12);
-        return AsconHash256{ .st = st };
+        return AsconHash256{ .st = st, .buf = @splat(0), .buf_len = 0 };
     }
 
     /// Compute Ascon-Hash256 hash of input data in one call.
@@ -630,24 +632,26 @@ pub const AsconHash256 = struct {
     pub fn update(self: *AsconHash256, b: []const u8) void {
         var i: usize = 0;
 
-        // Process full 64-bit blocks
-        while (i + 8 <= b.len) : (i += 8) {
-            self.st.addBytes(b[i..][0..8]);
+        if (self.buf_len > 0) {
+            const to_fill = @min(block_length - self.buf_len, b.len);
+            @memcpy(self.buf[self.buf_len..][0..to_fill], b[0..to_fill]);
+            self.buf_len += to_fill;
+            i += to_fill;
+            if (self.buf_len == block_length) {
+                self.st.addBytes(&self.buf);
+                self.st.permuteR(12);
+                self.buf_len = 0;
+            }
+        }
+
+        while (i + block_length <= b.len) : (i += block_length) {
+            self.st.addBytes(b[i..][0..block_length]);
             self.st.permuteR(12);
         }
 
-        // Store partial block for finalization
         if (i < b.len) {
-            var padded: [8]u8 = @splat(0);
-            const remaining = b.len - i;
-            @memcpy(padded[0..remaining], b[i..]);
-            padded[remaining] = 0x01;
-            self.st.addBytes(&padded);
-        } else {
-            // Add padding block
-            var padded: [8]u8 = @splat(0);
-            padded[0] = 0x01;
-            self.st.addBytes(&padded);
+            self.buf_len = b.len - i;
+            @memcpy(self.buf[0..self.buf_len], b[i..]);
         }
     }
 
@@ -658,6 +662,11 @@ pub const AsconHash256 = struct {
     ///
     /// Note: After calling final(), the hasher should not be used again
     pub fn final(self: *AsconHash256, out: *[digest_length]u8) void {
+        var padded: [block_length]u8 = @splat(0);
+        @memcpy(padded[0..self.buf_len], self.buf[0..self.buf_len]);
+        padded[self.buf_len] = 0x01;
+        self.st.addBytes(&padded);
+
         // Final permutation after padding
         self.st.permuteR(12);
 
```
