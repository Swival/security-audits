# receive length overreports copied bytes

## Classification

Data integrity bug, medium severity. Confidence: certain.

## Affected Locations

`library/std/src/sys/net/connection/xous/udp.rs:183`

## Summary

`UdpSocket::recv_inner` copied at most `buf.len()` bytes into the caller buffer, but returned the datagram-reported `rxlen` unconditionally. When a UDP datagram was larger than the caller-provided buffer, public receive APIs could report that more bytes were read or peeked than were actually written.

## Provenance

Verified from the provided source and reproducer summary. Initially identified by Swival Security Scanner: https://swival.dev

## Preconditions

- A UDP datagram is received by the Xous UDP implementation.
- The datagram length reported by the net server, `rxlen`, exceeds the caller-provided receive buffer length.
- The caller uses `recv_from`, `recv`, `peek_from`, or `peek`.

## Proof

In `recv_inner`, the net server response length is parsed from bytes `rr[1..3]`:

```rust
let rxlen = u16::from_le_bytes(rr[1..3].try_into().unwrap());
```

The payload copy uses iterator `zip`:

```rust
for (&s, d) in rr[22..22 + rxlen as usize].iter().zip(buf.iter_mut()) {
    *d = s;
}
```

`zip` stops at the shorter iterator, so if `rxlen > buf.len()`, only `buf.len()` bytes are written.

The function then returned the original reported datagram length:

```rust
Ok((rxlen as usize, addr))
```

Thus, for a 2-byte datagram and a 1-byte receive buffer, the function wrote 1 byte but returned `Ok((2, addr))`. Public wrappers propagated that value through `recv_from`, `recv`, `peek_from`, and `peek`.

## Why This Is A Real Bug

The public API contract is to return the number of bytes read or peeked into the provided buffer. Returning a length larger than the number of bytes actually copied is observably incorrect.

Safe callers commonly use the returned length to slice the receive buffer, such as `&buf[..n]`; when `n > buf.len()`, this can panic. Unsafe callers may also trust the returned length and treat bytes that were never initialized by this receive operation as valid data.

## Fix Requirement

When the received datagram length exceeds the caller-provided buffer length, the implementation must report the number of bytes actually copied, or otherwise handle truncation consistently with an error. It must not return a byte count larger than the bytes written into `buf`.

## Patch Rationale

The patch computes the copied length as the minimum of the reported datagram length and the caller buffer length:

```rust
let len = (rxlen as usize).min(buf.len());
```

It then copies only that many bytes from the response payload and returns the same value:

```rust
for (&s, d) in rr[22..22 + len].iter().zip(buf.iter_mut()) {
    *d = s;
}
Ok((len, addr))
```

This makes the returned byte count match the actual number of bytes written to the caller-provided buffer.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/udp.rs b/library/std/src/sys/net/connection/xous/udp.rs
index ce54ea3b79e..9e292ebf0ce 100644
--- a/library/std/src/sys/net/connection/xous/udp.rs
+++ b/library/std/src/sys/net/connection/xous/udp.rs
@@ -178,10 +178,11 @@ fn recv_inner(&self, buf: &mut [u8], do_peek: bool) -> io::Result<(usize, Socket
                 } else {
                     return Err(io::const_error!(io::ErrorKind::Other, "library error"));
                 };
-                for (&s, d) in rr[22..22 + rxlen as usize].iter().zip(buf.iter_mut()) {
+                let len = (rxlen as usize).min(buf.len());
+                for (&s, d) in rr[22..22 + len].iter().zip(buf.iter_mut()) {
                     *d = s;
                 }
-                Ok((rxlen as usize, addr))
+                Ok((len, addr))
             }
         } else {
             Err(io::const_error!(io::ErrorKind::InvalidInput, "unable to recv"))
```