# IP-address TLS endpoints skip hostname verification

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:489`
`src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:542`
`src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:751`
`src/http_jsc/websocket_client/WebSocketUpgradeClient.rs:793`

## Summary

IP-literal `wss://` WebSocket connections with `rejectUnauthorized: true` validated only the certificate chain and skipped endpoint identity verification. Because the client did not store an IP host for later TLS identity checks and only called `check_server_identity` when SNI/servername existed, a trusted certificate for any unrelated name could be accepted for an IP-address URL.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- `rejectUnauthorized` is true.
- TLS certificate chain validates under a trusted CA.
- Victim connects to a `wss://<IP>/` URL.
- Attacker can intercept or impersonate the network endpoint and present any CA-trusted server certificate for a different identity.

## Proof

- `connect` stored `hostname` only when the dialed host was not an IP literal, so IP-address `wss://` URLs left `hostname` empty.
- `handle_open` configured TLS SNI only when `hostname` was non-empty.
- `handle_handshake` rejected nonzero `ssl_error.error_no`, but that value reflects chain validation, not endpoint-name validation.
- `handle_handshake` then called `SSL_get_servername` and only invoked `boringssl::check_server_identity` inside `if !servername.is_null()`.
- For IP-literal URLs, no SNI was configured, `SSL_get_servername` returned null, the hostname-verification branch was skipped, and the successful TLS handshake was accepted.
- A network attacker with any CA-trusted certificate for another hostname could complete TLS and proceed with the WebSocket upgrade for `wss://<IP>/`.

## Why This Is A Real Bug

`rejectUnauthorized: true` is expected to reject certificates whose identity does not match the URL endpoint. Chain validation alone only proves that a trusted CA issued the certificate; it does not prove that the certificate is valid for the requested IP address. The previous control flow deterministically failed open for IP-literal hosts because endpoint identity verification was conditional on SNI/servername, which is absent for IP endpoints.

## Fix Requirement

Always verify the peer certificate against the URL host when `rejectUnauthorized` is true, including IP-literal hosts. IP addresses must not be sent as SNI, but they must still be retained as the expected identity and checked against certificate IP SANs.

## Patch Rationale

- The patch stores non-empty URL hosts in `hostname` even when they are IP literals.
- `handle_open` suppresses SNI for IP literals by passing null to TLS configuration, preserving correct SNI behavior.
- `hostname` is no longer cleared after TLS configuration, so `handle_handshake` can use the original URL host for identity verification.
- `handle_handshake` now prefers the stored URL host for `check_server_identity`, falls back to servername only if no stored host exists, and fails closed if no hostname is available.
- This decouples endpoint verification from SNI presence and ensures IP-literal endpoints are validated against the certificate identity.

## Residual Risk

None

## Patch

```diff
diff --git a/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs b/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
index c3f48b94cd..d94982d85d 100644
--- a/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
+++ b/src/http_jsc/websocket_client/WebSocketUpgradeClient.rs
@@ -489,9 +489,7 @@ impl<const SSL: bool> HTTPClient<SSL> {
                         // `tls: { checkServerIdentity }` or put the hostname
                         // in the URL (wss+unix://name/path) to verify against
                         // a specific certificate name.
-                        if !host_slice.slice().is_empty()
-                            && !strings::is_ip_address(host_slice.slice())
-                        {
+                        if !host_slice.slice().is_empty() {
                             client_ref.hostname = ZBox::from_bytes(host_slice.slice());
                         }
                     }
@@ -539,7 +537,7 @@ impl<const SSL: bool> HTTPClient<SSL> {
                     // SNI for the outer TLS socket must use the host we actually
                     // dialed. For HTTPS proxy connections, that's the proxy host,
                     // not the wss:// target.
-                    if !strings::is_ip_address(display_host_) {
+                    if !display_host_.is_empty() {
                         out.hostname = ZBox::from_bytes(display_host_);
                     }
                 }
@@ -749,15 +747,21 @@ impl<const SSL: bool> HTTPClient<SSL> {
                 // Keep the raw pointer — round-tripping through `&c_char` would
                 // shrink provenance to 1 byte and make the CStr scan UB.
                 let servername = unsafe { boringssl::c::SSL_get_servername(ssl_ptr, 0) };
-                if !servername.is_null() {
+                let hostname = if !this.hostname.is_empty() {
+                    this.hostname.as_bytes()
+                } else if !servername.is_null() {
                     // SAFETY: SSL_get_servername returns a NUL-terminated C string
                     // owned by the SSL session; full provenance retained above.
-                    let hostname = unsafe { bun_core::ffi::cstr(servername) }.to_bytes();
-                    // SAFETY: ssl_ptr is a live `*SSL` from the open socket.
-                    if !boringssl::check_server_identity(unsafe { &mut *ssl_ptr }, hostname) {
-                        // SAFETY: no `&mut Self` is live across this call.
-                        unsafe { Self::fail(this.as_ptr(), ErrorCode::TlsHandshakeFailed) };
-                    }
+                    unsafe { bun_core::ffi::cstr(servername) }.to_bytes()
+                } else {
+                    b""
+                };
+                // SAFETY: ssl_ptr is a live `*SSL` from the open socket.
+                if hostname.is_empty()
+                    || !boringssl::check_server_identity(unsafe { &mut *ssl_ptr }, hostname)
+                {
+                    // SAFETY: no `&mut Self` is live across this call.
+                    unsafe { Self::fail(this.as_ptr(), ErrorCode::TlsHandshakeFailed) };
                 }
             }
         } else {
@@ -790,11 +794,14 @@ impl<const SSL: bool> HTTPClient<SSL> {
                     // boringssl::SSL; use bun_http's helper.
                     bun_http::configure_http_client_with_alpn(
                         handle,
-                        me.hostname.as_ptr(),
+                        if strings::is_ip_address(me.hostname.as_bytes()) {
+                            core::ptr::null()
+                        } else {
+                            me.hostname.as_ptr()
+                        },
                         bun_http::AlpnOffer::H1,
                     );
                 }
-                me.hostname = ZBox::default();
             }
         }
```