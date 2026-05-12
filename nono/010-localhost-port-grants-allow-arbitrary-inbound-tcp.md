# Localhost-port grants emit blanket inbound TCP on macOS

## Classification

security_control_failure, medium severity, confidence certain.

## Affected Locations

- `crates/nono/src/sandbox/macos.rs:687`
- `crates/nono/src/sandbox/macos.rs:732`

## Summary

When a macOS Seatbelt profile is generated for `NetworkMode::Blocked` or
`NetworkMode::ProxyOnly` and `localhost_ports` is non-empty,
`generate_profile` emits scoped `network-outbound` rules for the requested
ports and then also emits unqualified `(allow network-bind)` and
`(allow network-inbound)`. Seatbelt has no port granularity for bind or
inbound, so granting a single localhost port via `--open-port` results in
the child being able to bind and accept on any TCP port, including
`0.0.0.0:*`.

This is a known tradeoff documented on the builder in `crates/nono/src/capability.rs`:

> On macOS: outbound is per-port via Seatbelt; bind/inbound is blanket
> (same tradeoff as `--allow-bind`).

The CLI surface tells a different story. `--open-port` (`allow_port`) is
described as "Allow bidirectional localhost TCP on a port: connect + listen
(repeatable)", which an operator naturally reads as scoped to the listed
port. The gap between the per-port mental model in the CLI help and the
blanket bind/inbound emitted on macOS is the actual footgun.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Target platform is macOS.
- `CapabilitySet` uses `NetworkMode::Blocked` or `NetworkMode::ProxyOnly`.
- `localhost_ports` is non-empty (`--open-port` or `allow_localhost_port`).
- `tcp_bind_ports` (`--listen-port`) is empty — i.e. the operator did not
  explicitly opt into a blanket bind allow.

## Proof

For `--block-net --open-port 3000` the generated profile contains:

```scheme
(deny network*)
(allow network-outbound (remote tcp "localhost:3000"))
(allow network-bind)
(allow network-inbound)
```

Both `network-bind` and `network-inbound` are unqualified. A sandboxed
child can therefore `bind(127.0.0.1:4444)` or `bind(0.0.0.0:4444)` and
accept inbound connections, even though the operator only granted port
`3000`.

## Why This Is Worth Fixing

`--listen-port` (`tcp_bind_ports`) already exists as the explicit, opt-in
flag for the "I accept that bind/inbound is blanket on macOS" case. With
both flags present, `--open-port` carrying the blanket as a side effect is
strictly more permissive than the principle of least privilege requires.
Removing the implicit blanket from `--open-port` makes the two flags
behave consistently: connect granularity is per-port everywhere, and the
blanket bind/inbound is reached only by explicitly asking for it via
`--listen-port`.

This is a behaviour change. Callers that today rely on
`allow_localhost_port` to also enable `bind()/accept()` on the same port
on macOS must now combine `--open-port` with `--listen-port` (or use the
library equivalents). The capability-set documentation should be updated
to match.

## Fix Requirement

Stop emitting blanket `(allow network-bind)` / `(allow network-inbound)`
purely because `localhost_ports` is non-empty. Keep emitting them when
`tcp_bind_ports` is non-empty, which is the explicit bind opt-in.

## Patch Rationale

The patch:

- In the `Blocked` branch, drops the unconditional bind/inbound allows
  that follow the per-port outbound rules; only the TCP `system-socket`
  rules and scoped `network-outbound` rules remain.
- In the `ProxyOnly` branch, narrows the bind/inbound gate from
  "`!bind_ports.is_empty() || !localhost_ports.is_empty()`" to
  "`!bind_ports.is_empty()`".
- Updates the corresponding unit tests to assert that
  `localhost_ports`-only profiles do not contain `(allow network-bind)`
  or `(allow network-inbound)`.

## Residual Risk

Operators that need both connect and listen on a localhost port on macOS
must combine `--open-port` with `--listen-port`. Seatbelt still cannot
filter bind/inbound by port, so `--listen-port` remains a documented
blanket allow on macOS.

## Patch

```diff
diff --git a/crates/nono/src/sandbox/macos.rs b/crates/nono/src/sandbox/macos.rs
index 47273ad..583d74c 100644
--- a/crates/nono/src/sandbox/macos.rs
+++ b/crates/nono/src/sandbox/macos.rs
@@ -685,7 +685,7 @@ fn generate_profile(caps: &CapabilitySet) -> Result<String> {
             // grants use a non-recursive regex.
             emit_unix_socket_rules(&mut profile, caps)?;
             if !localhost_ports.is_empty() {
-                // Allow system-socket for TCP (required for connect/bind)
+                // Allow system-socket for TCP (required for connect)
                 profile.push_str(
                     "(allow system-socket (socket-domain AF_INET) (socket-type SOCK_STREAM))\n",
                 );
@@ -698,9 +698,6 @@ fn generate_profile(caps: &CapabilitySet) -> Result<String> {
                         lp
                     ));
                 }
-                // Seatbelt cannot filter bind/inbound by port
-                profile.push_str("(allow network-bind)\n");
-                profile.push_str("(allow network-inbound)\n");
             }
         }
         NetworkMode::ProxyOnly { port, bind_ports } => {
@@ -726,10 +723,9 @@ fn generate_profile(caps: &CapabilitySet) -> Result<String> {
             profile.push_str(
                 "(allow system-socket (socket-domain AF_INET6) (socket-type SOCK_STREAM))\n",
             );
-            // If bind ports or localhost IPC ports are specified, allow network-bind
-            // and network-inbound. Seatbelt cannot filter bind/inbound by port,
-            // so this is a blanket allow.
-            if !bind_ports.is_empty() || !localhost_ports.is_empty() {
+            // If bind ports are specified, allow network-bind and network-inbound.
+            // Seatbelt cannot filter bind/inbound by port, so this is a blanket allow.
+            if !bind_ports.is_empty() {
                 profile.push_str("(allow network-bind)\n");
                 profile.push_str("(allow network-inbound)\n");
             }
@@ -1700,8 +1696,8 @@ mod tests {
         assert!(profile.contains("(deny network*)"));
         assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:3000\"))"));
         assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:5000\"))"));
-        assert!(profile.contains("(allow network-bind)"));
-        assert!(profile.contains("(allow network-inbound)"));
+        assert!(!profile.contains("(allow network-bind)"));
+        assert!(!profile.contains("(allow network-inbound)"));
         assert!(profile.contains("(allow system-socket"));
         // Should allow DNS via mDNSResponder Unix socket (#588)
         assert!(
@@ -1724,9 +1720,8 @@ mod tests {
         assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:54321\"))"));
         // Localhost IPC port
         assert!(profile.contains("(allow network-outbound (remote tcp \"localhost:3000\"))"));
-        // Bind/inbound enabled because localhost_ports is non-empty
-        assert!(profile.contains("(allow network-bind)"));
-        assert!(profile.contains("(allow network-inbound)"));
+        assert!(!profile.contains("(allow network-bind)"));
+        assert!(!profile.contains("(allow network-inbound)"));
     }
 
     #[test]
```
