# Panic On Empty UDP Bind Addresses

## Classification

error-handling bug; severity: medium; confidence: certain

## Affected Locations

`library/std/src/sys/net/connection/motor.rs:242`

## Summary

`UdpSocket::bind` on the motor backend called `.next().unwrap()` on the iterator returned by `ToSocketAddrs`. Valid `ToSocketAddrs` inputs may resolve to an empty iterator, so the public `UdpSocket::bind` API could panic instead of returning `io::Error`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes `UdpSocket::bind` on the motor backend.
- The supplied `ToSocketAddrs` implementation returns `Ok` with no yielded addresses.
- A standard empty `&[SocketAddr]` input satisfies this condition.

## Proof

The vulnerable code path was:

```rust
let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
```

If `to_socket_addrs()` returns `Ok(empty_iterator)`, `.next()` returns `None` and `.unwrap()` panics before `moto_rt::net::bind` is called.

A practical trigger is an empty socket-address slice:

```rust
use std::net::{SocketAddr, UdpSocket};

let addrs: &[SocketAddr] = &[];
let _ = UdpSocket::bind(addrs); // panics on motor backend before patch
```

`ToSocketAddrs` explicitly permits empty iterators, and the standard implementation for `&[SocketAddr]` returns an iterator over the slice, so an empty slice is valid input.

## Why This Is A Real Bug

`UdpSocket::bind` is an error-returning public standard-library networking API. For valid inputs that yield no addresses, it must return an `io::Error`, not panic. Other backends route address iteration through `each_addr`, which returns `Error::NO_ADDRESSES` when no addresses are yielded; the motor backend violated that invariant by unwrapping `None`.

## Fix Requirement

Replace the unchecked `.unwrap()` with explicit empty-iterator handling that returns an `io::Error`, using `InvalidInput` for the no-addresses case.

## Patch Rationale

The patch preserves successful behavior while converting the empty-address case into a normal `io::Result` error:

```rust
let addr = addr
    .to_socket_addrs()?
    .next()
    .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "could not resolve to any addresses"))?;
let addr = into_netc(&addr);
```

This keeps address-resolution errors propagated by `?`, handles `None` without panicking, and only calls `into_netc` after a concrete `SocketAddr` exists.

## Residual Risk

None

## Patch

`051-panic-on-empty-udp-bind-addresses.patch`

```diff
diff --git a/library/std/src/sys/net/connection/motor.rs b/library/std/src/sys/net/connection/motor.rs
index 79a52879210..9976b53b878 100644
--- a/library/std/src/sys/net/connection/motor.rs
+++ b/library/std/src/sys/net/connection/motor.rs
@@ -238,7 +238,11 @@ pub fn into_socket(self) -> Socket {
     }
 
     pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<UdpSocket> {
-        let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
+        let addr = addr
+            .to_socket_addrs()?
+            .next()
+            .ok_or(io::const_error!(io::ErrorKind::InvalidInput, "could not resolve to any addresses"))?;
+        let addr = into_netc(&addr);
         moto_rt::net::bind(moto_rt::net::PROTO_UDP, &addr)
             .map(|fd| Self { inner: unsafe { Socket::from_raw_fd(fd) } })
             .map_err(map_motor_error)
```