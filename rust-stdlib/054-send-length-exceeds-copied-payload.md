# send length exceeds copied payload

## Classification

Data integrity bug, medium severity.

## Affected Locations

`library/std/src/sys/net/connection/xous/udp.rs:242`

## Summary

`UdpSocket::send_to` encoded the advertised UDP payload length from `buf.len()` but only copied bytes that fit in `tx_req.raw[21..]`. Since `tx_req.raw` is 4096 bytes, the request can carry at most `4096 - 21 = 4075` payload bytes. Payloads longer than 4075 bytes created a malformed transmit request where the advertised length exceeded the copied payload.

## Provenance

Verified from the supplied source and reproduced finding. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller sends a UDP payload longer than 4075 bytes.
- The call reaches `UdpSocket::send_to` directly or through `UdpSocket::send`.

## Proof

`UdpSocket::send_to` constructs a fixed-size `SendData { raw: [0u8; 4096] }`.

The first 21 bytes are used for request metadata:

- `raw[0..2]`: destination port
- `raw[2]`: IP version
- `raw[3..]`: address bytes
- `raw[19..21]`: advertised payload length

The payload copy starts at `raw[21..]`, so only 4075 bytes are available.

Before the patch:

```rust
let len = buf.len() as u16;
let len_bytes = len.to_le_bytes();
tx_req.raw[19] = len_bytes[0];
tx_req.raw[20] = len_bytes[1];
for (&s, d) in buf.iter().zip(tx_req.raw[21..].iter_mut()) {
    *d = s;
}
```

For `buf.len() == 4076`:

- `len` is encoded as `4076`.
- The copy loop writes only `4075` bytes because `tx_req.raw[21..]` has length `4075`.
- The malformed request is sent via `try_lend_mut(... StdUdpTx(self.fd) ..., &mut tx_req.raw, ..., 4096)`.
- On success, `send_to` returns `Ok(len as usize)`, reporting `4076` bytes sent even though only `4075` bytes could be carried in the IPC request.

## Why This Is A Real Bug

The std-side request is internally inconsistent for payloads larger than 4075 bytes. The length field tells `net_server` to consume more payload bytes than the request buffer contains after the header. This violates the transmit request encoding invariant and can cause truncation or downstream interpretation of bytes that were not copied from the caller's payload.

The bug is reachable through both `send_to` and `send`.

## Fix Requirement

Reject payloads larger than the available request payload capacity before encoding the length field and copying bytes.

The maximum valid payload length is:

```text
tx_req.raw[21..].len() == 4075
```

## Patch Rationale

The patch adds an explicit bounds check immediately before length encoding:

```rust
if buf.len() > tx_req.raw[21..].len() {
    return Err(io::const_error!(io::ErrorKind::InvalidInput, "payload too large"));
}
```

This ensures that:

- The advertised length cannot exceed the copied payload capacity.
- `buf.len() as u16` remains safe for all accepted inputs because the accepted maximum is 4075.
- `send_to` no longer reports success for bytes that cannot fit in the IPC request.
- The existing request layout and copy logic remain unchanged for valid payload sizes.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/udp.rs b/library/std/src/sys/net/connection/xous/udp.rs
index ce54ea3b79e..4d89243477b 100644
--- a/library/std/src/sys/net/connection/xous/udp.rs
+++ b/library/std/src/sys/net/connection/xous/udp.rs
@@ -240,6 +240,9 @@ pub fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
                 }
             }
         }
+        if buf.len() > tx_req.raw[21..].len() {
+            return Err(io::const_error!(io::ErrorKind::InvalidInput, "payload too large"));
+        }
         let len = buf.len() as u16;
         let len_bytes = len.to_le_bytes();
         tx_req.raw[19] = len_bytes[0];
```