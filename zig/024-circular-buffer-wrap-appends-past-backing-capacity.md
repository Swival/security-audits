# Circular Buffer Wrap Appends Past Backing Capacity

## Classification

- Type: out-of-bounds write
- Severity: high
- Confidence: certain

## Affected Locations

- `lib/std/compress/lzma.zig:342`
- `Decode.CircularBuffer.set`
- Call path:
  - `Decompress.readIndirect`
  - `Decode.process`
  - `CircularBuffer.appendLiteral`
  - `CircularBuffer.set`

## Summary

`Decode.CircularBuffer.set` always appended to the backing `ArrayList` after ensuring capacity, even when the requested index already existed. After the LZMA dictionary cursor wrapped, writes to index `0` and subsequent wrapped indices should overwrite existing dictionary entries. Instead, they appended to `buf.items`, eventually writing past the backing allocation in unsafe builds.

An attacker-controlled LZMA stream that expands sufficiently beyond `dict_size` can trigger this condition.

## Provenance

Reported and reproduced from a verified Swival security finding.

Scanner: [Swival.dev Security Scanner](https://swival.dev)

## Preconditions

- The decompressor processes attacker-controlled LZMA input.
- The decompressed output exceeds the configured dictionary size.
- The stream expands sufficiently beyond the dictionary size to grow `buf.items.len` to the backing capacity after wraparound.

## Proof

`Decompress.readIndirect` calls `Decode.process`, which emits bytes through `CircularBuffer.appendLiteral` and `CircularBuffer.appendLz`.

`appendLiteral` writes to the current circular-buffer cursor:

```zig
try self.set(gpa, self.cursor, lit);
self.cursor += 1;
self.len += 1;

if (self.cursor == self.dict_size) {
    try writer.writeAll(self.buf.items);
    self.cursor = 0;
}
```

When `cursor == dict_size`, the buffer is flushed and `cursor` is reset to `0`, but `buf.items.len` is not reset or shrunk.

On the next wrapped write, `set(gpa, 0, lit)` executes:

```zig
try self.buf.ensureTotalCapacity(gpa, index + 1);
while (self.buf.items.len < index) {
    self.buf.appendAssumeCapacity(0);
}
self.buf.appendAssumeCapacity(value);
```

Because `buf.items.len` is already greater than `index`, the fill loop is skipped. The code then appends instead of overwriting `buf.items[0]`.

Reproduction confirmed:

- Safe builds hit an assertion in `ArrayList.appendAssumeCapacity`.
- `ReleaseFast` corrupts allocator metadata and later fails with invalid/corrupted free, consistent with an out-of-bounds write.

## Why This Is A Real Bug

The circular buffer invariant requires wrapped writes to replace existing dictionary bytes. The original implementation violates that invariant by appending on every `set`, regardless of whether `index` is already initialized.

Because `appendAssumeCapacity` assumes spare capacity and performs no bounds checks in unsafe builds, repeated post-wrap appends can write beyond the `ArrayList` backing allocation. The trigger is remotely controllable when LZMA input is untrusted.

## Fix Requirement

`CircularBuffer.set` must:

- append only when `index == buf.items.len`;
- overwrite when `index < buf.items.len`;
- preserve the existing memory-limit and capacity behavior.

## Patch Rationale

The patch keeps the original allocation and sparse-fill behavior, but distinguishes between extending the initialized length and updating an existing slot.

This restores circular-buffer semantics after cursor wraparound and prevents `appendAssumeCapacity` from being used when no append is logically required.

## Residual Risk

None

## Patch

```diff
diff --git a/lib/std/compress/lzma.zig b/lib/std/compress/lzma.zig
index 4e3c614616..0059cb2971 100644
--- a/lib/std/compress/lzma.zig
+++ b/lib/std/compress/lzma.zig
@@ -369,7 +369,11 @@ pub const Decode = struct {
             while (self.buf.items.len < index) {
                 self.buf.appendAssumeCapacity(0);
             }
-            self.buf.appendAssumeCapacity(value);
+            if (index == self.buf.items.len) {
+                self.buf.appendAssumeCapacity(value);
+            } else {
+                self.buf.items[index] = value;
+            }
         }
 
         /// Retrieve the last byte or return a default
```