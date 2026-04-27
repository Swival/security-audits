# unchecked ABI length advances cursor

## Classification

Invariant violation; high severity.

## Affected Locations

`library/std/src/sys/stdio/zkvm.rs:22`

## Summary

The zkVM stdin `read_buf` implementation trusted the byte count returned by `abi::sys_read` and passed it directly to `BorrowedCursor::advance`. If the ABI returned a count larger than the cursor capacity, the cursor could be advanced beyond the backing buffer, corrupting `BorrowedBuf` invariants and enabling later unsafe out-of-bounds behavior.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`abi::sys_read` returns a byte count greater than the requested capacity.

## Proof

`Stdin::read_buf` receives a caller-provided `BorrowedCursor` and passes `buf.capacity()` to `abi::sys_read`.

Before the patch:

```rust
let n = abi::sys_read(fileno::STDIN, buf.as_mut().as_mut_ptr().cast(), buf.capacity());
buf.advance(n);
```

There was no validation that `n <= buf.capacity()` before `buf.advance(n)`.

The reproducer confirmed this is reachable through `std::io::stdin().read_buf(...)` via:

`Stdin -> StdinLock -> BufReader<StdinRaw> -> StdinRaw -> sys::stdio::zkvm::Stdin`

For sufficiently large caller buffers, `BufReader` bypasses directly to the inner `read_buf` at `library/std/src/io/buffered/bufreader.rs:356`.

If `n` exceeds the cursor capacity, `BorrowedCursor::advance` can make `BorrowedBuf::filled` larger than the underlying slice length. Later operations relying on this invariant can perform unchecked out-of-bounds slicing, including `BorrowedBuf::filled()` at `library/core/src/io/borrowed_buf.rs:107`, which uses `get_unchecked(..self.filled)`.

## Why This Is A Real Bug

`BorrowedCursor::advance` relies on the caller upholding the invariant that the advanced byte count does not exceed available capacity. The zkVM stdin implementation violated that requirement by trusting an external ABI return value without checking it.

Although the issue requires abnormal ABI behavior, the standard library wrapper is the boundary that converts ABI results into Rust I/O state. It must reject impossible byte counts rather than corrupting `BorrowedBuf` state.

## Fix Requirement

Validate the returned byte count against the original cursor capacity before advancing the cursor. If the ABI reports more bytes than requested, return an error and do not call `buf.advance`.

## Patch Rationale

The patch stores the original capacity before the read, compares the ABI return value against it, and returns `InvalidData` if the ABI reports an impossible length:

```rust
let capacity = buf.capacity();
let n = abi::sys_read(fileno::STDIN, buf.as_mut().as_mut_ptr().cast(), capacity);
if n > capacity {
    return Err(io::const_error!(
        io::ErrorKind::InvalidData,
        "zkvm stdin read exceeded buffer capacity",
    ));
}
buf.advance(n);
```

This preserves the `BorrowedCursor` and `BorrowedBuf` invariants while keeping valid reads unchanged.

## Residual Risk

None

## Patch

`196-unchecked-abi-length-advances-cursor.patch`

```diff
diff --git a/library/std/src/sys/stdio/zkvm.rs b/library/std/src/sys/stdio/zkvm.rs
index 84496ac9373..44a4153aa22 100644
--- a/library/std/src/sys/stdio/zkvm.rs
+++ b/library/std/src/sys/stdio/zkvm.rs
@@ -18,7 +18,14 @@ fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
 
     fn read_buf(&mut self, mut buf: BorrowedCursor<'_>) -> io::Result<()> {
         unsafe {
-            let n = abi::sys_read(fileno::STDIN, buf.as_mut().as_mut_ptr().cast(), buf.capacity());
+            let capacity = buf.capacity();
+            let n = abi::sys_read(fileno::STDIN, buf.as_mut().as_mut_ptr().cast(), capacity);
+            if n > capacity {
+                return Err(io::const_error!(
+                    io::ErrorKind::InvalidData,
+                    "zkvm stdin read exceeded buffer capacity",
+                ));
+            }
             buf.advance(n);
         }
         Ok(())
```