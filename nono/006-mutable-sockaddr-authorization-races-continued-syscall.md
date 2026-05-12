# Mutable Sockaddr Authorization Races Continued Syscall

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`crates/nono/src/sandbox/linux.rs:1304`

## Summary

The proxy-only seccomp fallback authorized `connect(2)` and `bind(2)` using a mutable userspace `sockaddr` read from `/proc/PID/mem`, then resumed the original syscall with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. Because Linux copies the syscall `sockaddr` into kernel memory before seccomp notification, an attacker could race-rewrite the userspace buffer so the supervisor approved benign bytes while the kernel continued the original disallowed destination or bind address.

The patch removes the unsafe proxy-only fallback on kernels without Landlock `AccessNet`, leaving only the fail-closed full network block fallback.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Kernel lacks Landlock `AccessNet` support, i.e. Landlock ABI before V4.
- `ProxyOnly` network mode is requested.
- The previous proxy-only seccomp fallback is installed.
- The sandboxed child can run multiple threads and mutate the `sockaddr` buffer during notification handling.

## Proof

The reproduced exploit flow is:

- A sandboxed child creates an allowed `AF_INET` or `AF_INET6` socket.
- The seccomp proxy filter traps `connect` or `bind`.
- The kernel has already copied the original disallowed `sockaddr` before seccomp notification.
- Another child thread mutates the userspace `sockaddr` buffer to an allowed loopback proxy port or allowed bind port before supervisor inspection.
- `read_notif_sockaddr` reads the modified userspace bytes from `/proc/PID/mem`.
- The supervisor allows the request and calls `continue_notif`.
- `SECCOMP_USER_NOTIF_FLAG_CONTINUE` resumes the original syscall using the kernel-copied disallowed `sockaddr`.

Impact:

- `connect` can bypass `ProxyOnly` and perform direct TCP egress to a non-proxy host or port.
- `bind` can bind TCP ports outside `proxy_bind_ports`.
- The liveness check at `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:690` only verifies the notification still exists; it does not bind approved bytes to the syscall bytes.

## Why This Is A Real Bug

`read_notif_sockaddr` explicitly documents the unsafe condition: the kernel copies `sockaddr` before seccomp runs, while the supervisor reads a mutable userspace copy and later continues the syscall. Notification ID validation only proves the notification is still pending; it does not prove the inspected userspace `sockaddr` matches the kernel-copied syscall argument.

For open-file notifications this pattern is safe because the supervisor opens the approved path itself and injects a supervisor-owned fd. For `connect` and `bind`, the code continued the child’s original syscall, so authorization was not bound to the object actually used by the kernel.

## Fix Requirement

Do not continue child-owned `connect` or `bind` syscalls after authorizing mutable userspace `sockaddr` data. Valid fixes are:

- Deny proxy-only fallback when Landlock `AccessNet` is unavailable.
- Or replace continuation with supervisor-owned networking, such as performing the connect/bind in the supervisor and injecting an fd.

## Patch Rationale

The patch chooses the fail-closed option:

- `seccomp_network_fallback_mode` now maps `NetworkMode::ProxyOnly` to `SeccompNetFallback::None`.
- `apply_with_abi` therefore rejects proxy-only network filtering on kernels without Landlock `AccessNet`.
- The user-facing error message is updated to state that only full `--block-net` seccomp fallback is supported on those kernels.
- Existing Landlock V4+ behavior is unchanged because native Landlock `AccessNet` handles proxy-only network restrictions without this seccomp continuation race.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono/src/sandbox/linux.rs b/crates/nono/src/sandbox/linux.rs
index 6bc5275..2b26831 100644
--- a/crates/nono/src/sandbox/linux.rs
+++ b/crates/nono/src/sandbox/linux.rs
@@ -484,7 +484,7 @@ pub fn apply_with_abi(caps: &CapabilitySet, abi: &DetectedAbi) -> Result<Seccomp
                 SeccompNetFallback::None => {
                     return Err(NonoError::SandboxInit(
                         "Network filtering requested but kernel Landlock ABI doesn't support it \
-                         (requires V4+). On this kernel, only full --block-net or --proxy-only \
+                         (requires V4+). On this kernel, only full --block-net \
                          fallback via seccomp is supported."
                             .to_string(),
                     ));
@@ -1637,10 +1637,7 @@ pub fn seccomp_network_fallback_mode(caps: &CapabilitySet) -> SeccompNetFallback
                 SeccompNetFallback::None
             }
         }
-        NetworkMode::ProxyOnly { port, bind_ports } => SeccompNetFallback::ProxyOnly {
-            proxy_port: *port,
-            bind_ports: bind_ports.clone(),
-        },
+        NetworkMode::ProxyOnly { .. } => SeccompNetFallback::None,
         NetworkMode::AllowAll => SeccompNetFallback::None,
     }
 }
```