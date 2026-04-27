# Unchecked Empty Vectored Length Sum

## Classification

Data integrity bug, medium severity, confidence certain.

## Affected Locations

`library/std/src/io/util.rs:167`

`library/std/src/io/util.rs:206`

## Summary

`Empty::write_vectored` and `Write for &Empty::write_vectored` summed caller-provided `IoSlice` lengths with unchecked `usize` addition. If the combined logical length exceeded `usize::MAX`, the operation could panic in checked builds or wrap in unchecked builds, returning an incorrect consumed byte count.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

The finding was reproduced and patched from the provided source and patch evidence.

## Preconditions

A caller invokes `std::io::empty().write_vectored` or `(&std::io::empty()).write_vectored` with vectored buffers whose combined `IoSlice::len()` values exceed `usize::MAX`.

The individual slices can be valid while the combined logical length overflows, including through aliased large backing slices.

## Proof

At `library/std/src/io/util.rs:167`, `Empty::write_vectored` computed:

```rust
let total_len = bufs.iter().map(|b| b.len()).sum();
Ok(total_len)
```

At `library/std/src/io/util.rs:206`, `Write for &Empty::write_vectored` used the same unchecked pattern.

`IoSlice` lengths are `usize`. Summing them with `Iterator::sum::<usize>()` does not provide explicit overflow handling. When the aggregate length exceeds `usize::MAX`, the returned value is not a valid consumed byte count: it either panics under overflow checks or wraps to a smaller `usize` when unchecked.

This path is reachable through `std::io::empty().write_vectored` with caller-controlled `IoSlice` arrays.

## Why This Is A Real Bug

`Write::write_vectored` is specified as equivalent to writing concatenated buffers, and `Write::write` returns the number of bytes consumed. Returning a wrapped total violates that contract because callers may trust the consumed byte count to advance offsets, drain buffers, or update accounting.

A panic is also observable behavior for a valid API call shape where each individual `IoSlice` length is valid. The bug is therefore not merely theoretical arithmetic overflow; it changes the public `Write` result semantics.

## Fix Requirement

The length accumulation must use checked arithmetic.

If the logical total cannot be represented as `usize`, `write_vectored` must return an error instead of panicking or returning a wrapped `Ok(total_len)`.

## Patch Rationale

The patch replaces unchecked `sum()` with `try_fold` and `checked_add`:

```rust
let total_len = bufs.iter().try_fold(0usize, |acc, b| {
    acc.checked_add(b.len()).ok_or(io::ErrorKind::InvalidInput)
})?;
```

This preserves existing behavior for representable totals and converts overflow into `Err(ErrorKind::InvalidInput)`. Applying the same change to `Write for &Empty` closes the equivalent reachable implementation.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/io/util.rs b/library/std/src/io/util.rs
index a09c8bc0693..41b747060e5 100644
--- a/library/std/src/io/util.rs
+++ b/library/std/src/io/util.rs
@@ -165,7 +165,9 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
 
     #[inline]
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        let total_len = bufs.iter().map(|b| b.len()).sum();
+        let total_len = bufs.iter().try_fold(0usize, |acc, b| {
+            acc.checked_add(b.len()).ok_or(io::ErrorKind::InvalidInput)
+        })?;
         Ok(total_len)
     }
 
@@ -204,7 +206,9 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
 
     #[inline]
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        let total_len = bufs.iter().map(|b| b.len()).sum();
+        let total_len = bufs.iter().try_fold(0usize, |acc, b| {
+            acc.checked_add(b.len()).ok_or(io::ErrorKind::InvalidInput)
+        })?;
         Ok(total_len)
     }
```