# Panic on Empty Listener Bind Addresses

## Classification

error-handling bug; medium severity; confidence certain.

## Affected Locations

`library/std/src/sys/net/connection/motor.rs:173`

## Summary

Motor's `TcpListener::bind` consumes the first `ToSocketAddrs` result with `next().unwrap()`. If address resolution or the supplied address collection yields no addresses, the public `io::Result<TcpListener>` API panics instead of returning an `io::Error`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller invokes `TcpListener::bind` on Motor with a `ToSocketAddrs` value that yields an empty iterator.

A minimal public trigger is:

```rust
use std::net::{SocketAddr, TcpListener};

let addrs: &[SocketAddr] = &[];
let _ = TcpListener::bind(addrs);
```

## Proof

`TcpListener::bind` resolves the input and immediately unwraps the first address:

```rust
let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
```

For `TcpListener::bind(&[] as &[SocketAddr])`, `to_socket_addrs()` succeeds but returns an empty iterator. `next()` returns `None`, so `unwrap()` panics before `moto_rt::net::bind` is called.

The reproduced behavior is a caller-triggerable panic through a public networking API on `target_os = "motor"`.

## Why This Is A Real Bug

`TcpListener::bind` returns `io::Result<TcpListener>`, so invalid or unresolvable bind inputs must be represented as `Err`, not as a panic. Empty address iterators are valid outputs of `ToSocketAddrs`, including from an empty `&[SocketAddr]`.

Other standard networking helper code treats this condition as a no-addresses invalid-input error, matching the expected `io::Result` contract.

## Fix Requirement

Replace the unchecked `unwrap()` with an explicit `None` handling path that returns `io::ErrorKind::InvalidInput`.

## Patch Rationale

The patch preserves the existing successful path and only changes empty-iterator handling. `ok_or_else` converts `None` from `next()` into an `io::Error`, allowing `TcpListener::bind` to return `Err` as its signature promises.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/motor.rs b/library/std/src/sys/net/connection/motor.rs
index 79a52879210..57edd44bd49 100644
--- a/library/std/src/sys/net/connection/motor.rs
+++ b/library/std/src/sys/net/connection/motor.rs
@@ -170,7 +170,9 @@ pub fn into_socket(self) -> Socket {
     }
 
     pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<TcpListener> {
-        let addr = into_netc(&addr.to_socket_addrs()?.next().unwrap());
+        let addr = into_netc(&addr.to_socket_addrs()?.next().ok_or_else(|| {
+            io::Error::new(io::ErrorKind::InvalidInput, "could not resolve to any addresses")
+        })?);
         moto_rt::net::bind(moto_rt::net::PROTO_TCP, &addr)
             .map(|fd| Self { inner: unsafe { Socket::from_raw_fd(fd) } })
             .map_err(map_motor_error)
```