# VerifyFull skips hostname without SNI

## Classification

security_control_failure, high severity, confidence certain

## Affected Locations

`src/sql_jsc/mysql/MySQLConnection.rs:414`

## Summary

`SSLMode::VerifyFull` accepted a TLS connection when no SNI/server name was present. The code rejected certificate chain validation failures, but only performed hostname verification inside an `if !servername.is_null()` branch. When `SSL_get_servername()` returned null, hostname verification was skipped and the MySQL handshake continued.

## Provenance

Verified and reproduced from scanner output provided by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- `ssl_mode` is `VerifyFull`
- `reject_unauthorized` is enabled
- TLS handshake succeeds
- Certificate chain validation succeeds
- No SNI/server name is configured or sent

## Proof

The affected `do_handshake` path handles `SSLMode::VerifyCa | SSLMode::VerifyFull` together. After a successful TLS handshake, it rejects nonzero certificate chain errors:

```rust
if ssl_error.error_no != 0 {
    self.tls_status = TLSStatus::SslFailed;
    return Ok(false);
}
```

It then obtains the hostname from the TLS session via `SSL_get_servername`. Hostname verification is guarded by a null check:

```rust
let servername = unsafe { bun_boringssl_sys::SSL_get_servername(ssl_ptr, 0) };
if !servername.is_null() {
    let hostname = unsafe { bun_core::ffi::cstr(servername) }.to_bytes();
    if !bun_boringssl::check_server_identity(unsafe { &mut *ssl_ptr }, hostname) {
        self.tls_status = TLSStatus::SslFailed;
        return Ok(false);
    }
}
```

If `servername` is null, `check_server_identity` is not called. Execution then reaches:

```rust
self.send_handshake_response()?;
return Ok(true);
```

The reproducer confirms the uSockets TLS attach path only sets SNI when `sni` is non-null, so the SSL session can have no server name. In that state, `VerifyFull` accepts any CA-valid certificate for a different hostname.

## Why This Is A Real Bug

`VerifyFull` means both the certificate chain and the certificate identity must be verified against the intended host. The original code made hostname verification conditional on SNI being present in the TLS session. Absence of SNI is not evidence that hostname validation should be skipped; it is exactly the case where `VerifyFull` must use the configured target hostname or fail closed.

A malicious MySQL server or MITM with any CA-valid certificate for another hostname can pass chain validation and be accepted when the caller did not set SNI/serverName. This is a deterministic fail-open of the `VerifyFull` hostname verification control.

## Fix Requirement

In `VerifyFull`, require a configured hostname and always call `check_server_identity` with that hostname. If no configured hostname exists, fail the TLS handshake.

## Patch Rationale

The patch separates `VerifyFull` hostname verification from opportunistic SNI inspection. Instead of reading the hostname back from `SSL_get_servername`, it uses `self.tls_config.server_name()` as the intended verification identity.

The patched logic:

- Runs hostname verification only for `SSLMode::VerifyFull`
- Requires `tls_config.server_name()` to be non-null
- Fails closed with `TLSStatus::SslFailed` when no hostname is configured
- Always calls `check_server_identity` for `VerifyFull` using the configured hostname
- Preserves `VerifyCa` behavior as chain validation only

## Residual Risk

None

## Patch

```diff
diff --git a/src/sql_jsc/mysql/MySQLConnection.rs b/src/sql_jsc/mysql/MySQLConnection.rs
index 77382ca441..dfff246675 100644
--- a/src/sql_jsc/mysql/MySQLConnection.rs
+++ b/src/sql_jsc/mysql/MySQLConnection.rs
@@ -441,12 +441,14 @@ impl MySQLConnection {
                             .get_native_handle()
                             .map(|h| h.cast())
                             .unwrap_or(core::ptr::null_mut());
-                        // SAFETY: `ssl_ptr` is a live SSL* (handshake just succeeded).
-                        let servername =
-                            unsafe { bun_boringssl_sys::SSL_get_servername(ssl_ptr, 0) };
-                        if !servername.is_null() {
-                            // SAFETY: SSL_get_servername returns a NUL-terminated C string
-                            // borrowed for the SSL session lifetime.
+                        if self.ssl_mode == SSLMode::VerifyFull {
+                            let servername = self.tls_config.server_name();
+                            if servername.is_null() {
+                                self.tls_status = TLSStatus::SslFailed;
+                                return Ok(false);
+                            }
+                            // SAFETY: `server_name` is a NUL-terminated C string owned by
+                            // `tls_config` for the connection lifetime.
                             let hostname = unsafe { bun_core::ffi::cstr(servername) }.to_bytes();
                             // SAFETY: `ssl_ptr` is non-null and live (see above).
                             if !bun_boringssl::check_server_identity(
```