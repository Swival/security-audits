# Unix Socket Permissions Applied After Bind

## Classification

Authorization bypass, medium severity, certain confidence.

## Affected Locations

`src/connmgr/server.rs:2001`

## Summary

`Server::new` created configured Unix listeners with `UnixListener::bind(path)` before applying the configured mode, user, or group. The socket path was reachable during that interval with creation-time permissions, allowing a lower-privileged local process to connect before the intended access controls were enforced.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- Server listens on a configured Unix socket.
- The Unix socket is configured with restrictive `mode`, `user`, or `group`.
- The parent directory is reachable by the attacker.
- The process umask and initial socket ownership leave the newly-created socket connectable by the attacker before post-bind permission changes.

## Proof

The vulnerable path first removes any existing socket file, then binds the Unix socket path:

```rust
fs::remove_file(path)
UnixListener::bind(path)
```

Only after `bind` does it apply access control:

```rust
fs::set_permissions(path, perms)
set_user(path, user)
set_group(path, group)
```

A reproduced AF_UNIX probe confirmed the operating-system behavior:

- With umask `000`, the socket was `0777` immediately after `bind`.
- A client connected before `chmod(0)`.
- The listener accepted and read from that connection after the restrictive chmod.
- A later connection attempt after `chmod(0)` failed with permission denied.

The server then accepts queued Unix connections and processes them normally through `Listener::run` and `NetStream::Unix`, with no peer-credential authorization check to reject a connection that raced the permission update.

## Why This Is A Real Bug

Unix socket permissions gate pathname-based future connects; they do not revoke already-connected or already-queued connections. Because the server binds first and restricts the socket later, an attacker can win the startup race and retain an unauthorized accepted connection even after the configured permissions are applied.

## Fix Requirement

Ensure the socket is never publicly connectable before configured Unix socket access controls are in place. This can be done by binding under a restrictive umask when restrictive `mode`, `user`, or `group` settings are configured, then immediately applying ownership and final permissions.

## Patch Rationale

The patch wraps `UnixListener::bind(path)` with a temporary `umask(0o777)` whenever Unix socket access controls are configured. This makes the socket non-connectable at creation time, closing the race window before ownership and final mode are applied.

The patch then applies `user` and `group` before the final mode. This avoids briefly granting permissions to the wrong owner/group when the final mode is more permissive than `000`.

When no `mode`, `user`, or `group` is configured, the code preserves the prior behavior and binds without changing the process umask.

## Residual Risk

None

## Patch

```diff
diff --git a/src/connmgr/server.rs b/src/connmgr/server.rs
index 7c13b9bb..886a7ca4 100644
--- a/src/connmgr/server.rs
+++ b/src/connmgr/server.rs
@@ -1998,19 +1998,24 @@ impl Server {
                         Err(e) => panic!("{}", e),
                     }
 
-                    let l = match UnixListener::bind(path) {
+                    let (l, socket_mode) = if mode.is_some() || user.is_some() || group.is_some()
+                    {
+                        let old_umask = unsafe { libc::umask(0o777) };
+                        let bind_result = UnixListener::bind(path);
+                        unsafe {
+                            libc::umask(old_umask);
+                        }
+
+                        (bind_result, Some((*mode).unwrap_or(0o777 & !old_umask)))
+                    } else {
+                        (UnixListener::bind(path), None)
+                    };
+
+                    let l = match l {
                         Ok(l) => l,
                         Err(e) => return Err(format!("failed to bind {:?}: {}", path, e)),
                     };
 
-                    if let Some(mode) = mode {
-                        let perms = fs::Permissions::from_mode(*mode);
-
-                        if let Err(e) = fs::set_permissions(path, perms) {
-                            return Err(format!("failed to set mode on {:?}: {}", path, e));
-                        }
-                    }
-
                     if let Some(user) = user {
                         if let Err(e) = set_user(path, user) {
                             return Err(format!(
@@ -2029,6 +2034,14 @@ impl Server {
                         }
                     }
 
+                    if let Some(mode) = socket_mode {
+                        let perms = fs::Permissions::from_mode(mode);
+
+                        if let Err(e) = fs::set_permissions(path, perms) {
+                            return Err(format!("failed to set mode on {:?}: {}", path, e));
+                        }
+                    }
+
                     let addr = l.local_addr().unwrap();
 
                     info!("listening on {:?}", addr);
```