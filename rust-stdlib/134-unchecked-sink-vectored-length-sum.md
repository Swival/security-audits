# unchecked Sink vectored length sum

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

- `library/std/src/io/util.rs:380`
- `library/std/src/io/util.rs:419`

## Summary

`Sink::write_vectored` and `&Sink::write_vectored` summed caller-controlled `IoSlice` lengths with unchecked `usize` accumulation. If the logical vectored input length exceeded `usize::MAX`, the sum could wrap in unchecked builds or panic with overflow checks enabled, causing an incorrect byte-count result or unexpected failure instead of a controlled error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes public stable `std::io::sink().write_vectored` or `Write for &Sink`.
- Caller supplies vectored buffers whose total logical length exceeds `usize::MAX`.
- Individual `IoSlice` lengths remain valid, but their aggregate length overflows `usize`.

## Proof

Caller-controlled `IoSlice` lengths entered `write_vectored` and were accumulated by:

```rust
let total_len = bufs.iter().map(|b| b.len()).sum();
```

This uses unchecked `usize` addition inside `Iterator::sum`.

A safe caller can construct multiple `IoSlice`s that alias the same large immutable buffer, so the aggregate logical input length can exceed `usize::MAX` without requiring separately allocated buffers totaling that size. On 32-bit targets, three aliases of a buffer around 1.43GB are sufficient: each slice is below the per-slice validity limit, while the total exceeds `u32::MAX`.

The result is either wrapped accounting, such as `Ok(0)` or another small value, or a panic when overflow checks are enabled.

## Why This Is A Real Bug

`Write::write_vectored` is public and stable, and its return value reports the number of bytes accepted from the concatenated buffers. `Sink` semantically consumes all input, so returning a wrapped byte count breaks caller accounting and progress assumptions. Panicking on valid safe inputs is also inconsistent with the expected fallible I/O contract.

The same unchecked pattern was present in both `Sink` and `&Sink` implementations.

## Fix Requirement

Replace unchecked summation with checked accumulation. If the total length cannot be represented as `usize`, return an I/O error instead of wrapping or panicking.

## Patch Rationale

The patch changes the accumulation to `try_fold` with `checked_add`:

```rust
let total_len = bufs.iter().try_fold(0usize, |total, buf| {
    total.checked_add(buf.len()).ok_or(io::ErrorKind::InvalidInput)
})?;
```

This preserves the existing success behavior for representable totals while converting overflow into `InvalidInput`. Applying the same change to both `Sink` and `&Sink` keeps their behavior consistent.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/io/util.rs b/library/std/src/io/util.rs
index a09c8bc0693..530bc8e8b33 100644
--- a/library/std/src/io/util.rs
+++ b/library/std/src/io/util.rs
@@ -378,7 +378,9 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
 
     #[inline]
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        let total_len = bufs.iter().map(|b| b.len()).sum();
+        let total_len = bufs.iter().try_fold(0usize, |total, buf| {
+            total.checked_add(buf.len()).ok_or(io::ErrorKind::InvalidInput)
+        })?;
         Ok(total_len)
     }
 
@@ -417,7 +419,9 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
 
     #[inline]
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        let total_len = bufs.iter().map(|b| b.len()).sum();
+        let total_len = bufs.iter().try_fold(0usize, |total, buf| {
+            total.checked_add(buf.len()).ok_or(io::ErrorKind::InvalidInput)
+        })?;
         Ok(total_len)
     }
```