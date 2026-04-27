# unchecked write_all_at offset addition

## Classification

Invariant violation, medium severity, confidence certain.

## Affected Locations

`library/std/src/os/unix/fs.rs:334`

## Summary

`FileExt::write_all_at` advances its caller-supplied `u64` offset after each successful partial write using unchecked addition. If `offset + n` exceeds `u64::MAX`, the next write offset wraps instead of reporting an error, violating the method's maintained invariant that each subsequent write starts immediately after the prior write.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes stable Unix `FileExt::write_all_at`.
- The initial offset is near `u64::MAX`.
- The `write_at` implementation returns `Ok(n)` with `n > 0` at that high offset.
- The remaining buffer is non-empty after that partial write.

## Proof

A safe custom Unix `FileExt` implementation that returns `Ok(1)` from `write_at` reproduces the bug.

Calling:

```rust
write_all_at(&[1, 2], u64::MAX)
```

causes the default implementation to:

1. Call `write_at` at offset `18446744073709551615`.
2. Receive `Ok(1)`.
3. Slice the remaining buffer to `[2]`.
4. Execute unchecked `offset += n as u64`.
5. Wrap the offset to `0`.
6. Call `write_at` for the remaining byte at offset `0`.
7. Return `Ok(())`.

The reproduced write offsets are therefore:

```text
18446744073709551615
0
```

instead of an error after the first successful write.

## Why This Is A Real Bug

`write_all_at` is a stable default trait method and is reachable by safe callers through Unix `FileExt` implementors. Its contract is to continuously write the entire buffer starting from the requested offset. Wrapping from `u64::MAX` to `0` means the remaining bytes are written to the wrong logical location while the method reports success.

The issue is the default-method invariant violation, not a demonstrated bug in the committed Unix `std::fs::File` Linux backend. On the tested Linux path, `std::fs::File` uses `pwrite64` and rejects offsets near `u64::MAX` before a successful short write occurs. Custom safe `FileExt` implementations whose `write_at` accepts high `u64` offsets can still trigger the wraparound.

## Fix Requirement

Advance the offset with checked arithmetic. If `offset.checked_add(n as u64)` fails, return an `io::ErrorKind::InvalidInput` error instead of wrapping and continuing at an incorrect offset.

## Patch Rationale

The patch preserves existing behavior for all non-overflowing writes and changes only the overflow case. Returning `InvalidInput` is appropriate because the caller-provided offset and successful byte count cannot form a valid next `u64` file offset.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/unix/fs.rs b/library/std/src/os/unix/fs.rs
index 219b340b924..ec773d17564 100644
--- a/library/std/src/os/unix/fs.rs
+++ b/library/std/src/os/unix/fs.rs
@@ -335,7 +335,10 @@ fn write_all_at(&self, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
                 }
                 Ok(n) => {
                     buf = &buf[n..];
-                    offset += n as u64
+                    offset = offset.checked_add(n as u64).ok_or(io::const_error!(
+                        io::ErrorKind::InvalidInput,
+                        "offset overflow",
+                    ))?;
                 }
                 Err(ref e) if e.is_interrupted() => {}
                 Err(e) => return Err(e),
```