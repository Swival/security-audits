# VerifyFull Skips Hostname Check Without Configured SNI

## Classification

Security control failure; high severity; confidence: certain.

## Affected Locations

`src/sql_jsc/postgres/PostgresSQLConnection.rs:665`

## Summary

`SSLMode::VerifyFull` accepted a chain-trusted certificate for the wrong hostname when the TLS session had no configured SNI/server name. The certificate chain error was checked, but hostname identity verification was conditional on `SSL_get_servername(...)` returning a value. If no server name was present, `BoringSSL::check_server_identity` was skipped and the handshake was accepted.

## Provenance

Reported by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- Client uses `SSLMode::VerifyFull`.
- `reject_unauthorized` is enabled.
- TLS configuration has no configured server name/SNI.
- Peer presents a certificate chain trusted by the configured CA store, but not valid for the intended PostgreSQL hostname.

## Proof

In `on_handshake`, the certificate verification path runs only when `reject_unauthorized` is enabled. For `SSLMode::VerifyFull`, the code first rejects chain validation failures via `ssl_error.error_no != 0`.

After that, hostname validation was guarded by:

```rust
if let Some(servername) =
    unsafe { BoringSSL::c::SSL_get_servername(ssl_ptr, 0).as_ref() }
{
    ...
    BoringSSL::check_server_identity(...)
}
```

When `SSL_get_servername` returned `None`, execution skipped `BoringSSL::check_server_identity` entirely and returned without failing the connection. Therefore, a chain-trusted certificate for a different hostname was accepted.

The reproduced result confirmed this narrower source-grounded behavior: SNI absence is client/configuration state, not server-controlled, but `VerifyFull` deterministically failed open when no configured server name was available.

## Why This Is A Real Bug

`VerifyFull` requires both certificate chain validation and hostname identity validation. Accepting a trusted certificate without checking that it matches the configured PostgreSQL hostname defeats the hostname verification security control.

This permits impersonation by any endpoint that can present a certificate chaining to a trusted CA, even if that certificate is issued for another hostname.

## Fix Requirement

For `SSLMode::VerifyFull`, require a configured hostname/server name and always call `BoringSSL::check_server_identity` with that configured hostname. If no hostname is configured, fail the handshake.

`SSLMode::VerifyCa` should continue to validate only the certificate chain.

## Patch Rationale

The patch changes hostname verification from “check if SNI exists on the SSL object” to “for `VerifyFull`, require the configured TLS server name.”

This is correct because the configured connection hostname is the identity that must be authenticated. The SSL session’s SNI value is not a valid optional gate for hostname verification. If no configured server name exists, `VerifyFull` cannot be satisfied and the connection must fail.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sql_jsc/postgres/PostgresSQLConnection.rs b/src/sql_jsc/postgres/PostgresSQLConnection.rs
index 7bbb6586b1..1ea24564a0 100644
--- a/src/sql_jsc/postgres/PostgresSQLConnection.rs
+++ b/src/sql_jsc/postgres/PostgresSQLConnection.rs
@@ -876,22 +876,24 @@ impl PostgresSQLConnection {
                             return;
                         }
 
-                        // SAFETY: native handle of a connected TLS socket is `SSL*`.
-                        let ssl_ptr: *mut BoringSSL::c::SSL = self
-                            .socket
-                            .get()
-                            .get_native_handle()
-                            .map_or(core::ptr::null_mut(), |p| p.cast());
-                        if let Some(servername) =
-                            unsafe { BoringSSL::c::SSL_get_servername(ssl_ptr, 0).as_ref() }
-                        {
-                            // SAFETY: SSL_get_servername returns a NUL-terminated C string.
-                            let hostname = unsafe {
-                                bun_core::ffi::cstr(
-                                    std::ptr::from_ref(servername).cast::<core::ffi::c_char>(),
-                                )
+                        if self.ssl_mode == SSLMode::VerifyFull {
+                            let servername = self.tls_config.server_name();
+                            if servername.is_null() {
+                                let Ok(v) = verify_error_to_js(&ssl_error, self.global()) else {
+                                    return;
+                                };
+                                self.fail_with_js_value(v);
+                                return;
                             }
-                            .to_bytes();
+
+                            // SAFETY: native handle of a connected TLS socket is `SSL*`.
+                            let ssl_ptr: *mut BoringSSL::c::SSL = self
+                                .socket
+                                .get()
+                                .get_native_handle()
+                                .map_or(core::ptr::null_mut(), |p| p.cast());
+                            // SAFETY: `servername` is a NUL-terminated C string owned by `tls_config`.
+                            let hostname = unsafe { bun_core::ffi::cstr(servername) }.to_bytes();
                             // SAFETY: `ssl_ptr` is the live SSL* of a connected TLS socket.
                             if !BoringSSL::check_server_identity(unsafe { &mut *ssl_ptr }, hostname)
                             {
```