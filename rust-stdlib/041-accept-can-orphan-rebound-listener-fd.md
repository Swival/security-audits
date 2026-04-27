# accept can orphan rebound listener fd

## Classification

Race condition, medium severity, confidence certain.

## Affected Locations

`library/std/src/sys/net/connection/xous/tcplistener.rs:170`

## Summary

`TcpListener::accept` replaces the shared listener file descriptor after a successful accept. Before the patch, concurrent `accept` calls on cloned listener handles could each create a rebound listener fd and then blindly store it into the shared atomic. The later store overwrote the earlier rebound fd, making that fd unreachable and preventing `Drop` from closing it.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Two cloned `TcpListener` handles call `accept` concurrently and both accept paths succeed.

## Proof

Before the patch:

- `accept` passed `self.fd.load(Ordering::Relaxed)` directly into `StdTcpAccept`.
- On success, it called `TcpListener::bind_inner` to create a replacement listener fd.
- It then used `self.fd.store(new_fd, Ordering::Relaxed)` to publish the replacement.
- If two accept/rebind paths overlapped, both could allocate a `new_fd`.
- The later store overwrote the earlier stored fd.
- `Drop` only closes the fd currently stored in the shared atomic, so the overwritten fd had no remaining Rust owner and was not closed.

The reproduced behavior confirmed the lost ownership and cleanup gap.

## Why This Is A Real Bug

The overwritten rebound listener fd remains open in the Xous net service but is no longer reachable through any `TcpListener`. This leaks a socket/listener resource and can leave listener state alive without any Rust handle capable of accepting from it or closing it. The race is reachable through cloned listeners because `duplicate` shares the same atomic fd across handles.

## Fix Requirement

The accept/rebind handoff must be serialized or must atomically update ownership. If another concurrent accept already replaced the fd, the losing caller must close its newly allocated rebound fd instead of orphaning it.

## Patch Rationale

The patch records the fd used for `StdTcpAccept`, then publishes the rebound fd with `compare_exchange(fd, new_fd, Ordering::Relaxed, Ordering::Relaxed)`.

This ensures only the accept path that still observes the expected old fd installs its replacement. If the compare-exchange fails, another caller has already changed the shared fd, so the patch closes the losing `new_fd` with `StdTcpClose`. This preserves single ownership of the live listener fd and prevents unreachable rebound handles.

## Residual Risk

None

## Patch

```diff
diff --git a/library/std/src/sys/net/connection/xous/tcplistener.rs b/library/std/src/sys/net/connection/xous/tcplistener.rs
index 8818ef2ca9a..55b0f269391 100644
--- a/library/std/src/sys/net/connection/xous/tcplistener.rs
+++ b/library/std/src/sys/net/connection/xous/tcplistener.rs
@@ -121,9 +121,10 @@ pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
             receive_request.raw[0] = 1;
         }
 
+        let fd = self.fd.load(Ordering::Relaxed);
         if let Ok((_offset, _valid)) = crate::os::xous::ffi::lend_mut(
             services::net_server(),
-            services::NetLendMut::StdTcpAccept(self.fd.load(Ordering::Relaxed)).into(),
+            services::NetLendMut::StdTcpAccept(fd).into(),
             &mut receive_request.raw,
             0,
             0,
@@ -167,7 +168,17 @@ pub fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
                 // replenish the listener
                 let mut local_copy = self.local.clone(); // port is non-0 by this time, but the method signature needs a mut
                 let new_fd = TcpListener::bind_inner(&mut local_copy)?;
-                self.fd.store(new_fd, Ordering::Relaxed);
+                if self
+                    .fd
+                    .compare_exchange(fd, new_fd, Ordering::Relaxed, Ordering::Relaxed)
+                    .is_err()
+                {
+                    crate::os::xous::ffi::blocking_scalar(
+                        services::net_server(),
+                        services::NetBlockingScalar::StdTcpClose(new_fd).into(),
+                    )
+                    .unwrap();
+                }
 
                 // now return a stream converted from the old stream's fd
                 Ok((TcpStream::from_listener(stream_fd, self.local.port(), port, addr), addr))
```