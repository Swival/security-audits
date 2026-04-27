# unchecked read_buf_exact_at offset addition

## Classification

Invariant violation, medium severity, confidence certain.

## Affected Locations

`library/std/src/os/unix/fs.rs:210`

## Summary

`FileExt::read_buf_exact_at` advanced its caller-supplied `u64` offset with unchecked addition after each successful `read_buf_at` call. If the initial offset was near `u64::MAX` and bytes were appended to the cursor, `offset += n as u64` could overflow. Optimized builds wrap the offset, while overflow-checked builds panic, violating the expected monotonic file-position progression for an exact-at read.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes public `FileExt::read_buf_exact_at`.
- Caller supplies an offset near `u64::MAX`.
- `read_buf_at` succeeds and appends at least one byte to the `BorrowedCursor`.
- The cursor has remaining capacity, causing the loop to advance and potentially issue another read.

## Proof

`read_buf_exact_at` records `prev_written`, calls `self.read_buf_at(buf.reborrow(), offset)`, then computes progress as:

```rust
let n = buf.written() - prev_written;
offset += n as u64;
```

With `offset = u64::MAX` and `n = 1`, the addition overflows. In an optimized standard-library build this wraps to `0`; with overflow checks enabled it panics. The subsequent `n == 0` EOF check does not protect this path because the overflow occurs before that check and the triggering progress is nonzero.

A practical trigger exists because `FileExt` is public and `read_buf_exact_at` is a provided method. A custom implementation can implement the mandatory `read_at` method, or override `read_buf_at`, so that each call appends one byte. Calling `read_buf_exact_at` with cursor capacity at least two and `offset = u64::MAX` reaches the overflowing addition after the first successful byte.

## Why This Is A Real Bug

The method promises exact reading from a caller-provided offset independent of the current file cursor. Once the internal offset wraps, the next read can occur at the wrong logical file position. In overflow-checked builds, the same input unexpectedly panics instead of returning an `io::Error`. This is a semantic and invariant violation reachable through a public trait method, even though it is not memory unsafe.

## Fix Requirement

Replace unchecked offset advancement with checked addition. If advancing the offset would exceed `u64::MAX`, return an `io::ErrorKind::InvalidInput` error instead of wrapping or panicking.

## Patch Rationale

`checked_add` preserves monotonic offset progression by detecting the only invalid advancement state. Returning `InvalidInput` is appropriate because the caller-supplied offset and requested exact read length form an invalid range when their sum cannot be represented as `u64`. Existing behavior is unchanged for all non-overflowing reads.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/unix/fs.rs b/library/std/src/os/unix/fs.rs
index 219b340b924..cbee20910a9 100644
--- a/library/std/src/os/unix/fs.rs
+++ b/library/std/src/os/unix/fs.rs
@@ -208,7 +208,9 @@ fn read_buf_exact_at(&self, mut buf: BorrowedCursor<'_>, mut offset: u64) -> io:
                 Err(e) => return Err(e),
             }
             let n = buf.written() - prev_written;
-            offset += n as u64;
+            offset = offset.checked_add(n as u64).ok_or_else(|| {
+                io::Error::new(io::ErrorKind::InvalidInput, "offset overflow")
+            })?;
             if n == 0 {
                 return Err(io::Error::READ_EXACT_EOF);
             }
```