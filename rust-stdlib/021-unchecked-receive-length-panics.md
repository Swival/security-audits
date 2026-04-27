# Unchecked Receive Length Panics

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/tcpstream.rs:209`

## Summary

`TcpStream::read_or_peek` trusted the `length` returned by `os::xous::ffi::lend_mut` and used it as a slice bound into a fixed 4096-byte receive buffer. If `net_server` returned success metadata with `offset != 0` and `length > 4096`, safe `TcpStream::read` or `TcpStream::peek` could panic from an out-of-bounds slice.

## Provenance

Reproduced from a Swival Security Scanner finding: https://swival.dev

Confidence: certain.

## Preconditions

- `net_server` returns a successful receive response.
- The returned `offset` is nonzero.
- The returned `length` is greater than the receive buffer size, or greater than the requested read size.
- The caller reaches `TcpStream::read` or `TcpStream::peek`.

## Proof

`read_or_peek` allocates a fixed receive buffer:

```rust
let mut receive_request = ReceiveData { raw: [0u8; 4096] };
let data_to_read = buf.len().min(receive_request.raw.len());
```

It then calls `crate::os::xous::ffi::lend_mut`, which returns `(offset, length)` from syscall metadata. The reproduced evidence confirms the wrapper returns syscall registers as `Ok((a1, a2))` without validating `a2` against the lent buffer size.

On the successful receive path, the code used `length` directly:

```rust
if offset != 0 {
    for (dest, src) in buf.iter_mut().zip(receive_request.raw[..length].iter()) {
        *dest = *src;
    }
    Ok(length)
}
```

Because `receive_request.raw` is `[u8; 4096]`, any `length > 4096` makes `receive_request.raw[..length]` panic with an out-of-bounds slice.

## Why This Is A Real Bug

The affected APIs are safe Rust methods: `TcpStream::read` and `TcpStream::peek`. A malformed or buggy `net_server` response can therefore abort the caller instead of returning an `io::Error`.

The panic occurs before any validation, rejection, or clamping. The reported precondition is sufficient: `offset != 0` selects the data path, and `length > 4096` violates the fixed buffer bound at the slice operation.

## Fix Requirement

Validate the returned `length` before using it as a slice bound. The implementation must ensure `length <= receive_request.raw.len()` and should not copy or report more bytes than the caller requested.

## Patch Rationale

The patch clamps the returned `length` to `data_to_read`:

```rust
let length = length.min(data_to_read);
```

`data_to_read` is already computed as:

```rust
buf.len().min(receive_request.raw.len())
```

This simultaneously enforces both relevant bounds:

- the fixed receive buffer cannot be sliced past 4096 bytes;
- the caller's output buffer cannot be over-reported beyond the requested read size.

The existing copy loop and return value then operate on the bounded length.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/tcpstream.rs b/library/std/src/sys/net/connection/xous/tcpstream.rs
index 4df75453d1f..20492e73dd9 100644
--- a/library/std/src/sys/net/connection/xous/tcpstream.rs
+++ b/library/std/src/sys/net/connection/xous/tcpstream.rs
@@ -206,6 +206,7 @@ fn read_or_peek(&self, buf: &mut [u8], op: ReadOrPeek) -> io::Result<usize> {
         };
 
         if offset != 0 {
+            let length = length.min(data_to_read);
             for (dest, src) in buf.iter_mut().zip(receive_request.raw[..length].iter()) {
                 *dest = *src;
             }
```