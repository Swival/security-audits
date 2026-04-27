# unchecked receive length panics

## Classification

Validation gap, medium severity, certain confidence.

## Affected Locations

`library/std/src/sys/net/connection/xous/udp.rs:180`

## Summary

`UdpSocket::recv_inner` trusts the UDP receive length returned by `net_server`. If the response reports `rxlen > 4074`, the code slices past the end of the fixed 4096-byte receive buffer and panics before copying into the caller-provided buffer.

The patched code rejects receive lengths larger than the available payload area, `rr.len() - 22`, before constructing the payload slice.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- `net_server` returns a successful UDP receive response.
- `receive_request.raw[0] == 0`.
- `receive_request.raw[3]` is `4` or `6`.
- `rxlen = u16::from_le_bytes(rr[1..3])` is greater than `4074`.

## Proof

`recv_inner` receives data from `net_server` through `StdUdpRx(self.fd)` into `receive_request.raw`, a `[u8; 4096]`.

On a successful response, it parses:

```rust
let rr = &receive_request.raw;
let rxlen = u16::from_le_bytes(rr[1..3].try_into().unwrap());
```

Before the patch, it then copied payload bytes using:

```rust
for (&s, d) in rr[22..22 + rxlen as usize].iter().zip(buf.iter_mut()) {
    *d = s;
}
```

With `rxlen = 4075`, the slice end is `22 + 4075 = 4097`, which exceeds the 4096-byte array length. Rust bounds checking panics with an out-of-range slice error before `zip(buf.iter_mut())` can limit the copy.

The same vulnerable path is reachable through `recv_from`, `recv`, `peek_from`, and `peek`, because all call `recv_inner`.

## Why This Is A Real Bug

The length field is external data returned by `net_server`, but the std client code treated it as trusted when constructing an in-bounds slice.

The caller-provided destination buffer does not mitigate the issue because the panic occurs while creating `rr[22..22 + rxlen as usize]`, before iteration or truncation by `zip`.

A malformed or inconsistent successful receive response can therefore cause a deterministic panic in safe Rust code.

## Fix Requirement

Reject any `rxlen` larger than the payload capacity of the receive buffer before slicing:

```rust
rxlen as usize <= rr.len() - 22
```

If the value is invalid, return an `io::Error` instead of panicking.

## Patch Rationale

The patch adds a bounds check immediately after parsing `rxlen` and before using it in the payload slice:

```rust
if rxlen as usize > rr.len() - 22 {
    return Err(io::const_error!(io::ErrorKind::Other, "library error"));
}
```

This preserves the existing error style for malformed library/server responses while preventing out-of-bounds slice construction. Valid packets with payload lengths up to `4074` continue to follow the original path unchanged.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/udp.rs b/library/std/src/sys/net/connection/xous/udp.rs
index ce54ea3b79e..9a442365bb8 100644
--- a/library/std/src/sys/net/connection/xous/udp.rs
+++ b/library/std/src/sys/net/connection/xous/udp.rs
@@ -158,6 +158,9 @@ fn recv_inner(&self, buf: &mut [u8], do_peek: bool) -> io::Result<(usize, Socket
             } else {
                 let rr = &receive_request.raw;
                 let rxlen = u16::from_le_bytes(rr[1..3].try_into().unwrap());
+                if rxlen as usize > rr.len() - 22 {
+                    return Err(io::const_error!(io::ErrorKind::Other, "library error"));
+                }
                 let port = u16::from_le_bytes(rr[20..22].try_into().unwrap());
                 let addr = if rr[3] == 4 {
                     SocketAddr::new(IpAddr::V4(Ipv4Addr::new(rr[4], rr[5], rr[6], rr[7])), port)
```