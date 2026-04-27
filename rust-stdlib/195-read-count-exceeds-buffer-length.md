# read count exceeds buffer length

## Classification

Invariant violation, medium severity.

Confidence: certain.

## Affected Locations

`library/std/src/sys/stdio/uefi.rs:95`

## Summary

UEFI `Stdin::read` can return a byte count larger than the supplied buffer length when it already holds incomplete UTF-8 bytes and the next UTF-16 input character encodes to multiple UTF-8 bytes.

The bug also corrupts output data because the second partial character copy writes at the start of `buf` instead of the remaining free region.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was independently reproduced and patched.

## Preconditions

- `Stdin::read` is called with a non-empty `buf`.
- `self.incomplete_utf8` already contains buffered bytes from a prior partial UTF-8 character.
- The next UTF-16 key decodes to a `char` whose UTF-8 encoding does not fit in the remaining space of `buf`.
- The character encodes to multiple UTF-8 bytes.

## Proof

Concrete reproduced transition:

- First call uses vectored buffers `[1, 3]` and input `€`, where `len_utf8() == 3`.
- The default vectored read implementation reads only into the first non-empty slice at `library/std/src/io/mod.rs:538`.
- UEFI `Stdin::read` receives the 1-byte slice, writes 1 byte, and leaves 2 incomplete UTF-8 bytes buffered.
- Second call uses vectored buffers `[3, 1]` and input another `€`.
- UEFI `Stdin::read` receives only the first 3-byte slice.
- It first copies the 2 old incomplete bytes, so `bytes_copied == 2` and only 1 byte remains free.
- The new `€` does not fit.
- The buggy code calls `self.incomplete_utf8.read(buf)` instead of reading into `&mut buf[bytes_copied..]`.
- `IncompleteUtf8::read` copies from offset 0 of the full 3-byte buffer and returns 3.
- `bytes_copied` becomes `2 + 3 == 5`.
- `Stdin::read` returns `Ok(5)` for a 3-byte buffer.

## Why This Is A Real Bug

`io::Read::read` must not report more initialized bytes than fit in the caller-provided buffer.

The implementation violates that invariant by adding bytes written into the whole buffer after it has already counted bytes copied at the beginning of the same buffer. This creates two concrete failures:

- The returned count can exceed `buf.len()`.
- Newly copied partial UTF-8 bytes overwrite bytes already copied from the prior incomplete sequence.

The reproduced vectored-read case shows the public API can return `5` bytes read for only `4` bytes of total caller-provided storage.

## Fix Requirement

When writing a partial newly buffered UTF-8 character after existing incomplete bytes were copied, read only into the remaining free portion of `buf`.

Required change:

```rust
self.incomplete_utf8.read(&mut buf[bytes_copied..])
```

The returned value must then be added to `bytes_copied`, preserving the invariant that `bytes_copied <= buf.len()`.

## Patch Rationale

The patch changes the second incomplete UTF-8 drain from the entire buffer to the remaining buffer slice:

```diff
- bytes_copied += self.incomplete_utf8.read(buf);
+ bytes_copied += self.incomplete_utf8.read(&mut buf[bytes_copied..]);
```

This makes the destination offset consistent with the number of bytes already copied.

`IncompleteUtf8::read` already returns only the number of bytes copied into the slice it receives, so passing the remaining slice is sufficient to:

- avoid overwriting previously copied bytes;
- keep the returned byte count bounded by `buf.len()`;
- preserve any still-unwritten UTF-8 bytes in `self.incomplete_utf8`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/stdio/uefi.rs b/library/std/src/sys/stdio/uefi.rs
index ccd6bf658b0..6cf821eff8f 100644
--- a/library/std/src/sys/stdio/uefi.rs
+++ b/library/std/src/sys/stdio/uefi.rs
@@ -92,7 +92,7 @@ fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                     self.incomplete_utf8.len =
                         x.encode_utf8(&mut self.incomplete_utf8.bytes).len() as u8;
                     // write partial character to buffer.
-                    bytes_copied += self.incomplete_utf8.read(buf);
+                    bytes_copied += self.incomplete_utf8.read(&mut buf[bytes_copied..]);
                 }
             }
         }
```