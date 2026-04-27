# Oversized Unix Socket Address Length Panic

## Classification

Validation gap, medium severity.

## Affected Locations

`library/std/src/os/unix/net/addr.rs:237`

## Summary

`SocketAddr::from_parts` accepted an OS-provided `sockaddr_un` length without validating that it fit inside `sockaddr_un`. Later address inspection computed `len - SUN_PATH_OFFSET` and sliced `sun_path` with that derived length. If the kernel reported a length larger than the actual `sun_path` storage, safe APIs such as `Debug`, `is_unnamed`, or `as_abstract_name` could panic.

## Provenance

Found by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

- The OS returns an `AF_UNIX` `sockaddr_un` with `len > SUN_PATH_OFFSET + sun_path.len()`.
- Rust constructs a `SocketAddr` from that kernel-provided length through a getsockname-like callback.
- Caller later inspects or formats the returned `SocketAddr`.

## Proof

`SocketAddr::new` initializes a `sockaddr_un`, passes a mutable length to the OS callback, then calls `SocketAddr::from_parts(addr, len)`.

Before the patch, `from_parts` only handled `len == 0` and validated `sun_family`; it did not reject lengths larger than `size_of::<libc::sockaddr_un>()`.

`SocketAddr::address` then executed:

```rust
let len = self.len as usize - SUN_PATH_OFFSET;
let path = unsafe { mem::transmute::<&[libc::c_char], &[u8]>(&self.addr.sun_path) };
```

For abstract or pathname addresses it sliced `path` using that unchecked derived length:

```rust
AddressKind::Abstract(ByteStr::from_bytes(&path[1..len]))
AddressKind::Pathname(OsStr::from_bytes(&path[..len - 1]).as_ref())
```

The reproduced Darwin case had:

```text
sizeof(sockaddr_un) == 106
SUN_PATH_OFFSET == 2
sun_path.len() == 104
```

A raw `AF_UNIX` socket bound with sockaddr length `120` caused `getsockname` to report `outlen == 120`. `UnixDatagram::local_addr()` returned a `SocketAddr`, but formatting it panicked:

```text
local_addr succeeded; Debug will call SocketAddr::address
thread 'main' panicked at .../library/std/src/os/unix/net/addr.rs:251:58:
range end index 117 out of range for slice of length 104
```

The behavior was also reproduced through `UnixListener::accept`: a client bound with an oversized raw Unix sockaddr connected to a Rust `UnixListener`; `accept()` returned a `SocketAddr`, and logging the peer address panicked in `SocketAddr::address`.

## Why This Is A Real Bug

This is reachable through safe Rust APIs after the OS reports an oversized Unix-domain socket address length. The panic occurs during ordinary address inspection or formatting, including `Debug`, `is_unnamed`, and Linux abstract-name access.

The `UnixListener::accept` reproduction establishes a practical local attacker-controlled path: a local client can connect with an oversized bound Unix socket address, and a server that logs or inspects the peer address can be forced to panic.

## Fix Requirement

`SocketAddr::from_parts` must reject or clamp any length greater than `size_of::<libc::sockaddr_un>()` before storing it in `SocketAddr`.

## Patch Rationale

The patch rejects oversized lengths at construction time:

```rust
if len as usize > size_of::<libc::sockaddr_un>() {
    return Err(io::const_error!(
        io::ErrorKind::InvalidInput,
        "socket address length exceeded sockaddr_un size",
    ));
}
```

This preserves the invariant that `SocketAddr::len` never exceeds the backing `sockaddr_un` object. Consequently, `SocketAddr::address` cannot derive a `sun_path` length beyond the actual `sun_path` slice.

The check is placed after OpenBSD length normalization so that OpenBSD-specific behavior is handled first, and before `len == 0` handling and `SocketAddr` construction so invalid oversized lengths are never stored.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/os/unix/net/addr.rs b/library/std/src/os/unix/net/addr.rs
index 0748f6984a8..c9e4ebd4cf3 100644
--- a/library/std/src/os/unix/net/addr.rs
+++ b/library/std/src/os/unix/net/addr.rs
@@ -115,6 +115,13 @@ pub(super) fn from_parts(
                 .map_or(len, |new_len| (new_len + SUN_PATH_OFFSET) as libc::socklen_t);
         }
 
+        if len as usize > size_of::<libc::sockaddr_un>() {
+            return Err(io::const_error!(
+                io::ErrorKind::InvalidInput,
+                "socket address length exceeded sockaddr_un size",
+            ));
+        }
+
         if len == 0 {
             // When there is a datagram from unnamed unix socket
             // linux returns zero bytes of address
```