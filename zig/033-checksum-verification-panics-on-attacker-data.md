# zstd Checksum Verification Panics on Attacker Data

## Classification

Denial of service, medium severity.

Confidence: certain.

## Affected Locations

- `lib/std/compress/zstd/Decompress.zig:370`

## Summary

When zstd decompression is initialized with `Options.verify_checksum = true`, any valid checksummed frame that produces non-empty output reaches an unconditional `@panic`. A remote peer controlling compressed input can therefore terminate the decompression caller by supplying a non-empty zstd frame with the frame checksum flag set.

## Provenance

Verified by Swival security analysis and reproduction.

Scanner: https://swival.dev

## Preconditions

- The caller enables `Options.verify_checksum`.
- The attacker can supply zstd-compressed input to the decompressor.
- The supplied frame sets the zstd content checksum flag.
- At least one decoded block writes one or more output bytes.

## Proof

A minimal checksummed zstd frame reproduced the issue:

- zstd magic
- frame descriptor `0x24`: checksum flag set and single-segment flag set
- content size `1`
- one final raw block of size `1`
- one payload byte `"A"`
- checksum trailer present

The decompressor was initialized as:

```zig
std.compress.zstd.Decompress.init(&in, &.{}, .{ .verify_checksum = true })
```

Runtime result:

```text
panic: TODO all those bytes written needed to go through the hasher too
.../lib/std/compress/zstd/Decompress.zig:373:13 in readInFrame
```

Control flow:

1. `Decompress.init` stores `Options.verify_checksum`.
2. `initFrame` decodes the attacker-controlled frame header.
3. `Frame.init` sets `hasher_opt` when the frame checksum flag is present and checksum verification is enabled.
4. `readInFrame` decodes a raw, RLE, or compressed block and sets `bytes_written`.
5. If `hasher_opt` is present and `bytes_written > 0`, the code executes:

```zig
@panic("TODO all those bytes written needed to go through the hasher too");
```

## Why This Is A Real Bug

The panic is reachable from valid attacker-controlled compressed data under the documented checksum-verification option. It is not limited to malformed input or an internal invariant violation. In Zig, `@panic` aborts normal error handling and can terminate the process, making this an attacker-triggered denial of service for applications that enable checksum verification on untrusted streams.

The default `verify_checksum = false` avoids this path, but the enabled-checksum precondition is sufficient and realistic because checksum verification is an exposed option.

## Fix Requirement

Replace the panic with checksum hasher updates over the exact decompressed bytes emitted for the current block, then keep the existing final checksum comparison against the frame trailer.

## Patch Rationale

After each block decode, `bytes_written` records the number of output bytes appended to the writer. At that point `w.end` has advanced, so the newly emitted bytes are exactly:

```zig
w.buffer[w.end - bytes_written .. w.end]
```

Updating the frame hasher with that slice implements the missing checksum accumulation and preserves the existing behavior for zero-byte blocks and final trailer validation.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/compress/zstd/Decompress.zig b/lib/std/compress/zstd/Decompress.zig
index 8acb2650a2..e925414ed6 100644
--- a/lib/std/compress/zstd/Decompress.zig
+++ b/lib/std/compress/zstd/Decompress.zig
@@ -369,8 +369,7 @@ fn readInFrame(d: *Decompress, w: *Writer, limit: Limit, state: *State.InFrame)
 
     if (state.frame.hasher_opt) |*hasher| {
         if (bytes_written > 0) {
-            _ = hasher;
-            @panic("TODO all those bytes written needed to go through the hasher too");
+            hasher.update(w.buffer[w.end - bytes_written .. w.end]);
         }
     }
 
```