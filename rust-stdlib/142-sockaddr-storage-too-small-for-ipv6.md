# sockaddr_storage too small for IPv6

## Classification

Invariant violation, high severity.

## Affected Locations

`library/std/src/sys/pal/solid/abi/sockets.rs:117`

## Summary

The SOLID platform ABI defines `sockaddr_storage` as a 16-byte structure, but IPv6 socket addresses use `sockaddr_in6`, which is 28 bytes. Rust networking code passes `sockaddr_storage` to SOLID_NET APIs that may write IPv6 addresses into the supplied buffer. This violates the required storage invariant that `sockaddr_storage` must be large enough for any supported socket address.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- Target platform is `target_os = "solid_asp3"`.
- Code stores or receives an IPv6 socket address in `sockaddr_storage`.
- A result-address API is called, such as `TcpStream::peer_addr()`, `TcpStream::socket_addr()`, `TcpListener::accept()`, or `UdpSocket::recv_from()`.

## Proof

At `library/std/src/sys/pal/solid/abi/sockets.rs:117`, `sockaddr_storage` contains:

```rust
pub struct sockaddr_storage {
    pub s2_len: u8,
    pub ss_family: sa_family_t,
    pub s2_data1: [c_char; 2usize],
    pub s2_data2: [u32; 3usize],
}
```

This totals 16 bytes:

- `s2_len`: 1 byte
- `ss_family`: 1 byte
- `s2_data1`: 2 bytes
- `s2_data2`: 12 bytes

But `sockaddr_in6` contains:

- `sin6_len`: 1 byte
- `sin6_family`: 1 byte
- `sin6_port`: 2 bytes
- `sin6_flowinfo`: 4 bytes
- `sin6_addr`: 16 bytes
- `sin6_scope_id`: 4 bytes

This totals 28 bytes.

The conversion path expects the storage buffer to be large enough for either address family. For `AF_INET6`, `socket_addr_from_c` asserts that the supplied length is at least `size_of::<c::sockaddr_in6>()` before reading a `sockaddr_in6` from the buffer at `library/std/src/sys/net/connection/socket/mod.rs:200`.

SOLID_NET APIs such as `accept`, `getpeername`, `getsockname`, and `recvfrom` accept `sockaddr` pointers and may return IPv6 socket addresses through those pointers. Passing the current 16-byte `sockaddr_storage` buffer for an IPv6 result requires 28 bytes and can overflow or truncate the address data.

## Why This Is A Real Bug

The ABI type is used as generic socket-address storage, but it is smaller than a supported concrete socket-address type. IPv6 support is explicitly present through `AF_INET6`, `sockaddr_in6`, IPv6 socket options, and conversion logic that handles `AF_INET6`.

When an IPv6 address is returned into this buffer, the program can hit one of several invalid outcomes:

- External SOLID_NET code writes past the Rust stack object.
- The returned address is truncated.
- Rust conversion code rejects or aborts on the length invariant.
- Rust conversion code may read a `sockaddr_in6` from insufficient storage if length metadata is inconsistent.

All outcomes follow from the committed source violating the storage-size invariant.

## Fix Requirement

Define `sockaddr_storage` so that it is at least as large as `sockaddr_in6` and preserves suitable alignment for the contained address representations.

## Patch Rationale

The patch expands `sockaddr_storage::s2_data2` from three `u32` values to six `u32` values:

```diff
-    pub s2_data2: [u32; 3usize],
+    pub s2_data2: [u32; 6usize],
```

This changes the structure payload from 16 bytes to 28 bytes total:

- Prefix fields: 4 bytes
- `s2_data2`: 24 bytes
- Total: 28 bytes

That matches the size required by `sockaddr_in6` and preserves `u32` alignment for IPv6 fields such as `sin6_flowinfo` and `sin6_scope_id`.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/pal/solid/abi/sockets.rs b/library/std/src/sys/pal/solid/abi/sockets.rs
index 80802dd42e2..420ebf3975f 100644
--- a/library/std/src/sys/pal/solid/abi/sockets.rs
+++ b/library/std/src/sys/pal/solid/abi/sockets.rs
@@ -118,7 +118,7 @@ pub struct sockaddr_storage {
     pub s2_len: u8,
     pub ss_family: sa_family_t,
     pub s2_data1: [c_char; 2usize],
-    pub s2_data2: [u32; 3usize],
+    pub s2_data2: [u32; 6usize],
 }
 
 #[repr(C)]
```