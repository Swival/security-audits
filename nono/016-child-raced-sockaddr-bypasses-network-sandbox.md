# child-raced sockaddr bypasses network sandbox

## Classification

High severity policy bypass.

Confidence: certain.

## Affected Locations

- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:690`
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs:696`
- `crates/nono/src/sandbox/linux.rs:1970`

## Summary

In the proxy-only seccomp fallback, `handle_network_notification()` authorized `connect()` and `bind()` using a sockaddr snapshot read from child userspace memory, then resumed the original syscall with `SECCOMP_USER_NOTIF_FLAG_CONTINUE`.

Because the continued syscall still uses the child-controlled sockaddr pointer, a multithreaded sandboxed process could swap the sockaddr after the supervisor’s allow decision and before syscall continuation. This allowed connects or binds outside the intended network policy when Landlock AccessNet was unavailable.

## Provenance

Reported and reproduced by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The sandbox is using the proxy-only seccomp fallback for network mediation.
- The fallback handles `connect()` or `bind()` seccomp notifications.
- Landlock AccessNet enforcement is not available behind the fallback.
- The sandboxed child can mutate the sockaddr memory while the notification is pending.

## Proof

The supervisor flow was:

1. Receive a seccomp notification for `connect()` or `bind()`.
2. Read the sockaddr from child memory with `read_notif_sockaddr(notif.pid, args[1], args[2])`.
3. Check notification liveness with `notif_id_valid()`.
4. Decide policy from the copied `SockaddrInfo`.
5. On `NetworkDecision::Allow`, call `continue_notif()`.

`notif_id_valid()` only proves the seccomp notification is still pending. It does not freeze, copy, or bind the child’s pointed sockaddr to the supervisor’s policy decision.

A sandboxed multithreaded child can therefore:

1. Place an allowed sockaddr at the syscall pointer, such as `127.0.0.1:<proxy_port>`.
2. Trigger `connect()` or `bind()` and block in seccomp notify.
3. Wait for the supervisor to read and authorize that sockaddr.
4. Replace the pointed sockaddr with a disallowed external address or disallowed bind target.
5. Let the supervisor continue the original syscall.
6. Have the kernel complete the syscall using the attacker-mutated sockaddr.

Result: the child connects or binds outside the proxy-only network sandbox policy.

## Why This Is A Real Bug

The authorization object and execution object were not the same object.

The supervisor authorized a userspace snapshot read via `/proc/<pid>/mem`, but `continue_notif()` resumed the original child syscall rather than executing a supervisor-owned syscall or injecting an immutable object. Since the syscall arguments still referenced mutable child memory, the child retained control over the final sockaddr used by the kernel.

The existing TOCTOU check was insufficient because notification liveness is not sockaddr immutability.

## Fix Requirement

Do not call `SECCOMP_USER_NOTIF_FLAG_CONTINUE` for approved network syscalls when the policy decision depends on child-controlled sockaddr memory.

A complete safe design would either:

- perform the network operation in the supervisor using supervisor-owned immutable arguments, or
- otherwise revalidate an immutable kernel-copied sockaddr before allowing completion.

Until that mediation exists, the fallback must fail closed.

## Patch Rationale

The patch removes `continue_notif()` from the network notification allow path.

After policy evaluation, both `NetworkDecision::Allow` and `NetworkDecision::Deny` now respond with `EACCES`. This preserves fail-closed behavior and prevents the original `connect()` or `bind()` syscall from being resumed with a raced child sockaddr.

The documentation for `NetworkDecision` and `handle_network_notification()` was updated to reflect the security boundary: policy may classify a sockaddr as allowed, but response handling must still deny because continuing the original syscall is unsafe.

## Relation to finding 006

Finding 006 addresses the same race by disabling the proxy-only seccomp fallback altogether (`seccomp_network_fallback_mode` returns `None` for `NetworkMode::ProxyOnly`). With 006 applied, `handle_network_notification` is no longer reached on the proxy-only path, so this patch becomes belt-and-suspenders. The two patches are independent, do not conflict, and should both land: 006 removes the registration, 016 hardens the handler so any future re-introduction of a network notify path also fails closed.

## Residual Risk

None

## Patch

```diff
diff --git a/crates/nono-cli/src/exec_strategy/supervisor_linux.rs b/crates/nono-cli/src/exec_strategy/supervisor_linux.rs
index cf1786c..43fd28e 100644
--- a/crates/nono-cli/src/exec_strategy/supervisor_linux.rs
+++ b/crates/nono-cli/src/exec_strategy/supervisor_linux.rs
@@ -534,12 +534,13 @@ pub(super) fn handle_seccomp_notification(
 /// Decision produced by [`decide_network_notification`].
 ///
 /// Split out as an explicit type so the (testable) policy logic is decoupled
-/// from the (untestable) seccomp-notify response plumbing. Callers translate
-/// `Allow` to `continue_notif(…)` and `Deny` to `respond_notif_errno(…, EACCES)`.
+/// from the (untestable) seccomp-notify response plumbing. Until network
+/// syscalls can be mediated without re-reading child memory, callers fail
+/// closed even for `Allow` decisions.
 #[derive(Debug, Clone, Copy, PartialEq, Eq)]
 pub(super) enum NetworkDecision {
-    /// Let the kernel proceed with the already-copied sockaddr
-    /// (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`).
+    /// Policy would allow this sockaddr, but response handling may still
+    /// fail closed if it cannot safely mediate the syscall.
     Allow,
     /// Fail the syscall with `EACCES`.
     Deny,
@@ -656,16 +657,15 @@ pub(super) fn decide_network_notification(
 /// the sockaddr from the child's memory and delegates the allow/deny
 /// decision to [`decide_network_notification`].
 ///
-/// Uses SECCOMP_USER_NOTIF_FLAG_CONTINUE on approval (safe for connect/bind
-/// because the kernel has already copied sockaddr into kernel memory).
+/// Fails closed even on policy approval because continuing would let the
+/// original syscall re-read the child-controlled sockaddr pointer.
 pub(super) fn handle_network_notification(
     notify_fd: std::os::fd::RawFd,
     config: &SupervisorConfig<'_>,
     rate_limiter: &mut RateLimiter,
 ) -> nono::error::Result<()> {
     use nono::sandbox::{
-        continue_notif, deny_notif, notif_id_valid, read_notif_sockaddr, recv_notif,
-        respond_notif_errno,
+        deny_notif, notif_id_valid, read_notif_sockaddr, recv_notif, respond_notif_errno,
     };
 
     let notif = recv_notif(notify_fd)?;
@@ -695,14 +695,11 @@ pub(super) fn handle_network_notification(
 
     match decide_network_notification(notif.data.nr, &sockaddr, config) {
         NetworkDecision::Allow => {
-            // SECCOMP_USER_NOTIF_FLAG_CONTINUE: let the kernel proceed with its
-            // already-copied sockaddr. Safe for connect/bind (move_addr_to_kernel).
-            if let Err(e) = continue_notif(notify_fd, notif.id) {
-                debug!("continue_notif failed for network notification: {}", e);
-                // Must respond to avoid leaving the child blocked. Propagate if
-                // deny also fails — the notification is orphaned.
-                return deny_notif(notify_fd, notif.id);
-            }
+            debug!(
+                "Denying otherwise-allowed network notification: continuing connect/bind \
+                 would re-read child-controlled sockaddr"
+            );
+            respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
         }
         NetworkDecision::Deny => {
             respond_notif_errno(notify_fd, notif.id, libc::EACCES)?;
```