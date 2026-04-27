# Unchecked Vectored Write Length Sum

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/stdio/unsupported.rs:71`

## Summary

`Stdout::write_vectored` for unsupported stdio computes the total written byte count with an unchecked `usize` sum. If caller-supplied `IoSlice` lengths exceed `usize::MAX` in aggregate, the returned byte count can wrap in non-overflow-checking builds or panic when overflow checks are enabled.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller supplies `IoSlice` buffers whose combined lengths exceed `usize::MAX`.

## Proof

Caller-provided `IoSlice` lengths reach `Stdout::write_vectored` in `library/std/src/sys/stdio/unsupported.rs`.

The vulnerable implementation computes:

```rust
let total_len = bufs.iter().map(|b| b.len()).sum();
Ok(total_len)
```

Rust’s integer `Sum` implementation uses ordinary addition, so a combined length above `usize::MAX` overflows before `Ok(total_len)`. In unchecked builds this can wrap and report an incorrect byte count; in checked builds it can panic.

This path is reachable through `Write::write_vectored` on unsupported stdout and stderr. The unsupported implementation discards the data but still reports the number of bytes written, so incorrect accounting is observable by callers.

## Why This Is A Real Bug

`Write::write_vectored` returns the number of bytes accepted by the writer. Returning a wrapped value violates byte-accounting semantics and can cause callers to believe only a prefix was written even though the unsupported sink accepted all buffers.

The overflow condition is meaningful for vectored I/O because duplicated or aliased large `IoSlice`s can make accumulated lengths exceed `usize::MAX` without requiring physically distinct backing allocations. The standard library already accounts for this class of issue elsewhere, such as buffered vectored write length handling.

## Fix Requirement

Use checked addition when accumulating `IoSlice` lengths and return an error if the aggregate length overflows `usize`.

## Patch Rationale

The patch replaces unchecked `sum()` with `try_fold` plus `checked_add`.

On overflow, `write_vectored` now returns:

```rust
io::ErrorKind::InvalidInput
```

with message:

```text
vectored write length overflow
```

This preserves correct byte accounting for valid inputs and converts impossible-to-report aggregate lengths into an explicit error instead of wrapping or panicking.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/stdio/unsupported.rs b/library/std/src/sys/stdio/unsupported.rs
index 177264f5c10..2262fe8153c 100644
--- a/library/std/src/sys/stdio/unsupported.rs
+++ b/library/std/src/sys/stdio/unsupported.rs
@@ -68,7 +68,12 @@ fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
 
     #[inline]
     fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
-        let total_len = bufs.iter().map(|b| b.len()).sum();
+        let total_len = bufs.iter().try_fold(0usize, |total_len, buf| {
+            total_len.checked_add(buf.len()).ok_or(io::const_error!(
+                io::ErrorKind::InvalidInput,
+                "vectored write length overflow",
+            ))
+        })?;
         Ok(total_len)
     }
```