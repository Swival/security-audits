# read reports uncopied bytes

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/tcpstream.rs:212`

## Summary

`TcpStream::read_or_peek` trusted the `length` returned by the Xous `net_server` and returned it to callers even when it exceeded the caller-provided buffer length. The copy loop only wrote as many bytes as fit in `buf`, but the function reported the larger server-controlled `length`, violating Rust `Read` semantics.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- `net_server` returns success with `offset != 0`.
- The returned `length` is greater than the caller buffer length.
- The call reaches `TcpStream::read` or `TcpStream::peek`.

## Proof

In `read_or_peek`, the requested read size is capped:

```rust
let data_to_read = buf.len().min(receive_request.raw.len());
```

But after `lend_mut` succeeds, the returned `length` was previously used directly:

```rust
for (dest, src) in buf.iter_mut().zip(receive_request.raw[..length].iter()) {
    *dest = *src;
}
Ok(length)
```

The `zip` copy limits writes to `buf.len()`, so if `length > buf.len()`, fewer bytes are copied than reported. `TcpStream::read` and `TcpStream::peek` both reach this path through `read_or_peek`.

This violates the `Read::read` invariant that `Ok(n)` must satisfy `n <= buf.len()`. A caller that trusts the returned count can observe phantom bytes. Standard helpers can also be affected: `default_read_buf` advances by returned `n`, and `BorrowedCursor::advance_checked` asserts the cursor has enough capacity.

## Why This Is A Real Bug

The bug is not theoretical because `length` originates from an external Xous FFI response, while the local copy operation is bounded by the caller buffer. There was no local validation, clamp, or rejection before returning `Ok(length)`. Therefore a successful server response with an oversized `length` makes the API report bytes that were never copied.

## Fix Requirement

Clamp the reported byte count to the number of bytes that can actually be copied into the caller buffer, or reject oversized lengths before copying and returning.

## Patch Rationale

The patch clamps `length` to `data_to_read` before slicing, copying, and returning:

```rust
let length = length.min(data_to_read);
```

`data_to_read` is already the maximum safe and requested transfer size: `min(buf.len(), receive_request.raw.len())`. Clamping to it ensures:

- `receive_request.raw[..length]` stays within the local receive buffer.
- The copy loop cannot represent more bytes than were available to copy.
- `Ok(length)` cannot exceed `buf.len()`.
- `read` and `peek` preserve the `Read` reported-byte invariant.

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