# Panic on Empty Connect Addresses

## Classification

Error-handling bug; medium severity; denial-of-service via reachable panic in a stable public API.

## Affected Locations

`library/std/src/sys/net/connection/motor.rs:31`

## Summary

`TcpStream::connect` in the motor backend unwraps the first resolved socket address without checking whether address resolution produced any values. `ToSocketAddrs` may validly resolve to an empty iterator, so this path panics instead of returning an `io::Error`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

`ToSocketAddrs::to_socket_addrs` returns `Ok(iterator)` and the iterator yields no addresses.

## Proof

The vulnerable code evaluates:

```rust
let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
```

For an empty iterator, `next()` returns `None`, and `unwrap()` panics before `moto_rt::net::tcp_connect` is called.

A minimal trigger is:

```rust
use std::net::{SocketAddr, TcpStream};

let addrs: [SocketAddr; 0] = [];
let _ = TcpStream::connect(&addrs[..]);
```

This reaches public `TcpStream::connect` with a valid `ToSocketAddrs` input that resolves successfully but produces no socket addresses.

## Why This Is A Real Bug

`ToSocketAddrs` explicitly permits the returned iterator to yield no values. Other networking code handles this condition as an error, including the shared helper that returns `Error::NO_ADDRESSES` when no addresses are available.

The motor backend instead calls `unwrap()` on the first iterator item, converting a valid empty-resolution case into a process panic. This violates the expected `io::Result` error contract of `TcpStream::connect`.

## Fix Requirement

Replace the unchecked `unwrap()` with checked handling of `None` and return `io::Error::NO_ADDRESSES`.

## Patch Rationale

The patch preserves the existing flow for valid addresses while changing only the empty-address case. `ok_or(io::Error::NO_ADDRESSES)?` maps `None` into the same error used by shared networking code, avoiding the panic and keeping behavior consistent with the `io::Result` API.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/motor.rs b/library/std/src/sys/net/connection/motor.rs
index 79a52879210..f4bd863dad4 100644
--- a/library/std/src/sys/net/connection/motor.rs
+++ b/library/std/src/sys/net/connection/motor.rs
@@ -28,7 +28,7 @@ pub fn into_socket(self) -> Socket {
     }
 
     pub fn connect<A: ToSocketAddrs>(addr: A) -> io::Result<TcpStream> {
-        let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
+        let addr = into_netc(&addr.to_socket_addrs()?.next().ok_or(io::Error::NO_ADDRESSES)?);
         moto_rt::net::tcp_connect(&addr, Duration::MAX, false)
             .map(|fd| Self { inner: unsafe { Socket::from_raw_fd(fd) } })
             .map_err(map_motor_error)
```