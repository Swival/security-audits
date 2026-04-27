# Vectored Write Count Overflow

## Classification

Data integrity bug, medium severity.

Confidence: certain.

## Affected Locations

`library/std/src/io/buffered/linewritershim.rs:248`

## Summary

`LineWriterShim::write_vectored` can return an overflowing byte count after the inner vectored writer reports a near-`usize::MAX` successful write and the shim buffers additional tail bytes.

In release builds, the final `flushed + buffered` may wrap, commonly to `Ok(0)`, falsely reporting no progress after data was written and buffered. In checked/debug builds, the same addition can panic.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched.

## Preconditions

- The caller reaches `LineWriterShim::write_vectored`.
- The wrapped writer supports specialized vectored writes.
- The inner vectored writer reports a successful write count near `usize::MAX`.
- The input contains completed line buffers followed by tail buffers.
- At least one tail byte is buffered after the reported `flushed` count.

## Proof

The vulnerable path is:

1. `write_vectored` splits input into `lines` and `tail`.
2. `self.inner_mut().write_vectored(lines)?` returns `flushed`.
3. `lines_len` is accumulated with `saturating_add`, allowing saturated accounting to treat all line buffers as flushed.
4. Tail buffers are copied into the internal buffer.
5. The method returns `Ok(flushed + buffered)` without checking representability.

A practical safe 32-bit reproducer is:

```rust
use std::io::{self, IoSlice, LineWriter, Write};

fn main() {
    let mut data = vec![b'a'; 65_537];
    *data.last_mut().unwrap() = b'\n';

    // On 32-bit: 65_537 * 65_535 == usize::MAX.
    let mut bufs = vec![IoSlice::new(&data); 65_535];
    bufs.push(IoSlice::new(b"x"));

    let mut writer = LineWriter::with_capacity(1, io::sink());
    let n = writer.write_vectored(&bufs).unwrap();

    // Release std wraps to 0; checked/debug std panics on the addition.
    println!("{n}");
}
```

Observed impact: the writer consumes `usize::MAX` bytes via the inner writer and buffers one additional byte, but the total `usize::MAX + 1` cannot be represented as `usize`.

## Why This Is A Real Bug

`Write::write_vectored` returns the number of bytes accepted. Returning a wrapped count violates that contract.

In release builds, wrapping to `Ok(0)` falsely signals no progress even though data was consumed and buffered. Callers such as `write_all_vectored` may interpret `Ok(0)` as `WriteZero`, causing incorrect error handling and data-integrity failures.

In checked builds, the unchecked addition panics, making the same input a denial-of-service trigger.

## Fix Requirement

Only buffer tail bytes while `flushed + buffered` remains representable as `usize`.

The function must never perform an unchecked addition where the sum can exceed `usize::MAX`.

## Patch Rationale

The patch replaces iterator-based buffering and unchecked summation with an explicit loop that tracks remaining representable capacity:

- Skips empty tail buffers.
- Computes `spare = usize::MAX - flushed - buffered`.
- Stops buffering once no representable byte count remains.
- Slices each tail buffer to at most `spare` bytes before buffering.
- Breaks when `write_to_buf` accepts zero bytes.
- Preserves the final `Ok(flushed + buffered)` because the loop invariant guarantees it cannot overflow.

This keeps the reported count truthful and representable without changing normal behavior.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/io/buffered/linewritershim.rs b/library/std/src/io/buffered/linewritershim.rs
index 967e24812b9..c01d0e4e288 100644
--- a/library/std/src/io/buffered/linewritershim.rs
+++ b/library/std/src/io/buffered/linewritershim.rs
@@ -242,12 +242,21 @@ fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
 
         // Now that the write has succeeded, buffer the rest (or as much of the
         // rest as possible)
-        let buffered: usize = tail
-            .iter()
-            .filter(|buf| !buf.is_empty())
-            .map(|buf| self.buffer.write_to_buf(buf))
-            .take_while(|&n| n > 0)
-            .sum();
+        let mut buffered: usize = 0;
+        for buf in tail {
+            if buf.is_empty() {
+                continue;
+            }
+            let spare = usize::MAX - flushed - buffered;
+            if spare == 0 {
+                break;
+            }
+            let n = self.buffer.write_to_buf(&buf[..buf.len().min(spare)]);
+            if n == 0 {
+                break;
+            }
+            buffered += n;
+        }
 
         Ok(flushed + buffered)
     }
```