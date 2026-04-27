# accept masks invalid peer address

## Classification

Data integrity bug. Severity: medium. Confidence: certain.

## Affected Locations

`library/std/src/sys/net/connection/sgx.rs:306`

## Summary

`TcpListener::accept` on SGX accepted an unparseable peer address from `usercalls::accept_stream`, suppressed the parse failure, and returned `0.0.0.0:0` as the peer address. This returned a false peer identity through the public `TcpListener::accept` API instead of reporting the invalid address as an error.

## Provenance

Verified from the supplied source, reproduced behavior, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`usercalls::accept_stream` returns success with a valid UTF-8 but unparseable `peer_addr` string, such as `"local"` or `"not a socket addr"`.

## Proof

`TcpListener::accept` calls:

```rust
let (fd, local_addr, peer_addr) = usercalls::accept_stream(self.inner.inner.raw())?;
let peer_addr = Some(peer_addr);
let ret_peer =
    addr_to_sockaddr(peer_addr.as_deref()).unwrap_or_else(|_| ([0; 4], 0).into());
Ok((TcpStream { inner: Socket::new(fd, local_addr), peer_addr }, ret_peer))
```

`peer_addr` originates from the untrusted SGX usercall provider. It is parsed through `addr_to_sockaddr`, which calls `.to_socket_addrs()` and returns an error when parsing fails.

For non-IP strings, SGX `lookup_host_string` returns a `NonIpSockAddr` error, so inputs such as `"local"` fail conversion to `SocketAddr`.

Instead of propagating that failure, `accept` uses:

```rust
unwrap_or_else(|_| ([0; 4], 0).into())
```

This converts any parse error into `0.0.0.0:0` and still returns `Ok`.

## Why This Is A Real Bug

The public `TcpListener::accept` contract returns both the accepted `TcpStream` and the remote peer `SocketAddr`. Returning `0.0.0.0:0` for an invalid peer address is not equivalent to returning an error; it fabricates a peer identity.

The behavior is also internally inconsistent. The returned tuple contains `0.0.0.0:0`, while the returned `TcpStream` retains the original invalid `peer_addr`. A later `TcpStream::peer_addr()` call reuses `addr_to_sockaddr` and would fail instead of returning the same peer address reported by `accept`.

## Fix Requirement

Propagate `addr_to_sockaddr` errors from `TcpListener::accept` instead of substituting `0.0.0.0:0`.

## Patch Rationale

The patch changes:

```rust
let ret_peer =
    addr_to_sockaddr(peer_addr.as_deref()).unwrap_or_else(|_| ([0; 4], 0).into());
```

to:

```rust
let ret_peer = addr_to_sockaddr(peer_addr.as_deref())?;
```

This preserves the intended behavior for valid peer addresses and returns an error when the peer address cannot be parsed. It also makes `TcpListener::accept` consistent with `TcpStream::peer_addr`, which already propagates `addr_to_sockaddr` failures.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/sgx.rs b/library/std/src/sys/net/connection/sgx.rs
index 5735a5db488..248f26ddf45 100644
--- a/library/std/src/sys/net/connection/sgx.rs
+++ b/library/std/src/sys/net/connection/sgx.rs
@@ -297,8 +297,7 @@ pub fn socket_addr(&self) -> io::Result<SocketAddr> {
     pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
         let (fd, local_addr, peer_addr) = usercalls::accept_stream(self.inner.inner.raw())?;
         let peer_addr = Some(peer_addr);
-        let ret_peer =
-            addr_to_sockaddr(peer_addr.as_deref()).unwrap_or_else(|_| ([0; 4], 0).into());
+        let ret_peer = addr_to_sockaddr(peer_addr.as_deref())?;
         Ok((TcpStream { inner: Socket::new(fd, local_addr), peer_addr }, ret_peer))
     }
```