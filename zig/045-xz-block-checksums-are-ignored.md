# XZ block checksums are ignored

## Classification

- Type: security control failure
- Severity: high
- Confidence: certain

## Affected Locations

- `lib/std/compress/xz/Decompress.zig:135`
- Function: `readIndirect`

## Summary

XZ block integrity checks selected by stream flags were read but not verified. For `.crc32`, `.crc64`, and `.sha256`, the decoder consumed the declared block check value, discarded it, incremented `block_count`, and returned success.

As a result, an otherwise valid XZ stream with a corrupted or attacker-modified block payload could be accepted when callers rely on XZ block checks for integrity.

## Provenance

- Verified by Swival security analysis.
- Scanner provenance: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- The XZ stream flags select one of:
  - CRC32 block check
  - CRC64 block check
  - SHA256 block check
- The stream is otherwise structurally valid.
- The block check field is incorrect for the decompressed block bytes.

## Proof

`Decompress.init()` stores the stream-selected check type:

```zig
.check = stream_flags.check,
```

`readIndirect()` then decompresses a block through `readBlock()` and reads the declared block check:

```zig
switch (d.check) {
    .none => {},
    .crc32 => {
        const declared_checksum = try input.takeInt(u32, .little);
        // TODO
        _ = declared_checksum;
    },
    .crc64 => {
        const declared_checksum = try input.takeInt(u64, .little);
        // TODO
        _ = declared_checksum;
    },
    .sha256 => {
        const declared_hash = try input.take(Sha256.digest_length);
        // TODO
        _ = declared_hash;
    },
```

The declared checksum/hash is discarded. No computed checksum/hash is compared against it. Execution then continues:

```zig
d.block_count += 1;
return 0;
```

Runtime reproduction confirmed the fail-open behavior using fixture `good-1-check-crc32.xz`: flipping the first byte of the block CRC32 while leaving the stream otherwise valid still produced accepted decompressed output:

```text
accepted 13 bytes: Hello
World!
```

## Why This Is A Real Bug

XZ block checks are an integrity control. When stream flags request CRC32, CRC64, or SHA256 block checks, the decoder must compute the selected digest over the decompressed block bytes and reject mismatches.

The affected implementation instead accepts mismatched declared checksums. This deterministically disables the requested integrity check and allows corrupted or tampered block contents to be consumed by callers.

## Fix Requirement

For each decompressed block:

1. Record the start offset of newly produced uncompressed bytes.
2. After `readBlock()` completes, slice the newly written uncompressed block bytes.
3. Read the declared block check from the input.
4. Compute the selected check over the uncompressed block bytes.
5. If the computed and declared values differ, fail with `WrongChecksum`.

## Patch Rationale

The patch records `block_start` before decompression and derives `unpacked_bytes` after `readBlock()` finishes. It then implements verification for all supported XZ block check types:

- CRC32: `Crc32.hash(unpacked_bytes)`
- CRC64: `Crc64.hash(unpacked_bytes)`
- SHA256: `Sha256.hash(unpacked_bytes, ...)`

On mismatch, it stores `error.WrongChecksum` in `d.err` and returns `error.ReadFailed`, matching the existing reader error-propagation pattern used elsewhere in `readIndirect`.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/compress/xz/Decompress.zig b/lib/std/compress/xz/Decompress.zig
index 2fff561c73..4b97456fa8 100644
--- a/lib/std/compress/xz/Decompress.zig
+++ b/lib/std/compress/xz/Decompress.zig
@@ -134,6 +134,7 @@ fn readIndirect(r: *Reader) Reader.Error!usize {
     if (d.err != null) return error.ReadFailed;
     if (d.block_count == std.math.maxInt(usize)) return error.EndOfStream;
 
+    const block_start = allocating.writer.end;
     readBlock(input, &allocating) catch |err| switch (err) {
         error.WriteFailed => {
             d.err = error.OutOfMemory;
@@ -152,30 +153,33 @@ fn readIndirect(r: *Reader) Reader.Error!usize {
             return error.ReadFailed;
         },
     };
+    const unpacked_bytes = allocating.writer.buffer[block_start..allocating.writer.end];
     switch (d.check) {
         .none => {},
         .crc32 => {
             const declared_checksum = try input.takeInt(u32, .little);
-            // TODO
-            //const hash_a = Crc32.hash(unpacked_bytes);
-            //if (hash_a != hash_b) return error.WrongChecksum;
-            _ = declared_checksum;
+            const computed_checksum = Crc32.hash(unpacked_bytes);
+            if (computed_checksum != declared_checksum) {
+                d.err = error.WrongChecksum;
+                return error.ReadFailed;
+            }
         },
         .crc64 => {
             const declared_checksum = try input.takeInt(u64, .little);
-            // TODO
-            //const hash_a = Crc64.hash(unpacked_bytes);
-            //if (hash_a != hash_b) return error.WrongChecksum;
-            _ = declared_checksum;
+            const computed_checksum = Crc64.hash(unpacked_bytes);
+            if (computed_checksum != declared_checksum) {
+                d.err = error.WrongChecksum;
+                return error.ReadFailed;
+            }
         },
         .sha256 => {
             const declared_hash = try input.take(Sha256.digest_length);
-            // TODO
-            //var hash_a: [Sha256.digest_length]u8 = undefined;
-            //Sha256.hash(unpacked_bytes, &hash_a, .{});
-            //if (!std.mem.eql(u8, &hash_a, &hash_b))
-            //    return error.WrongChecksum;
-            _ = declared_hash;
+            var computed_hash: [Sha256.digest_length]u8 = undefined;
+            Sha256.hash(unpacked_bytes, &computed_hash, .{});
+            if (!std.mem.eql(u8, &computed_hash, declared_hash)) {
+                d.err = error.WrongChecksum;
+                return error.ReadFailed;
+            }
         },
         else => {
             d.err = error.Unsupported;
```