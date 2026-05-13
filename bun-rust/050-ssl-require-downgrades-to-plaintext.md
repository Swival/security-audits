# SSL Require Downgrades To Plaintext

## Classification

security_control_failure, high severity, certain confidence.

## Affected Locations

`src/sql_jsc/mysql/MySQLConnection.rs:662`

## Summary

`SSLMode::Require` failed open when the MySQL server handshake did not advertise `CLIENT_SSL`. A malicious MySQL server or network MITM could omit `CLIENT_SSL`, causing the client to skip TLS setup and continue authentication over the existing plaintext socket despite `ssl_mode=require`.

## Provenance

Verified by Swival.dev Security Scanner: https://swival.dev

## Preconditions

- The client connects with `ssl_mode` set to `Require`.
- The server handshake is controlled by a malicious MySQL server or network MITM.
- The hostile handshake omits `CLIENT_SSL`.

## Proof

- `handle_handshake` intersects desired client capabilities with server-advertised capabilities.
- If the hostile handshake omits `CLIENT_SSL`, the negotiated capabilities also omit `CLIENT_SSL`.
- The TLS request and socket upgrade path is skipped because `self.capabilities.CLIENT_SSL` is false.
- `tls_status` is then set to `TLSStatus::SslNotAvailable`.
- The fallback branch only rejected `SSLMode::VerifyCa` and `SSLMode::VerifyFull`.
- `SSLMode::Require` was explicitly allowed to continue with `Prefer` and `Disable`.
- Execution then reached `send_handshake_response()`, sending authentication on the non-TLS socket.
- For `caching_sha2_password`, full-auth continuation was worse because the later check used `ssl_mode == Disable` rather than actual TLS state, allowing `Require` to send the password as if TLS were active.

## Why This Is A Real Bug

`SSLMode::Require` means the connection must not proceed without TLS. The server handshake is attacker-controlled input in the threat model, and omitting `CLIENT_SSL` deterministically forced a plaintext fallback. This directly violates the security control and can expose authentication material over plaintext.

## Fix Requirement

Reject non-`CLIENT_SSL` handshakes when `ssl_mode` is `Require` or stronger.

## Patch Rationale

The patch moves `SSLMode::Require` into the same rejection path as `SSLMode::VerifyCa` and `SSLMode::VerifyFull` when TLS is unavailable. `SSLMode::Prefer` and `SSLMode::Disable` remain allowed to continue without TLS, preserving the intended fallback behavior only for modes that permit plaintext.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sql_jsc/mysql/MySQLConnection.rs b/src/sql_jsc/mysql/MySQLConnection.rs
index 77382ca441..afbe03af50 100644
--- a/src/sql_jsc/mysql/MySQLConnection.rs
+++ b/src/sql_jsc/mysql/MySQLConnection.rs
@@ -701,13 +701,10 @@ impl MySQLConnection {
             self.tls_status = TLSStatus::SslNotAvailable;
 
             match self.ssl_mode {
-                SSLMode::VerifyCa | SSLMode::VerifyFull => {
+                SSLMode::Require | SSLMode::VerifyCa | SSLMode::VerifyFull => {
                     return Err(AnyMySQLError::AuthenticationFailed);
                 }
-                // require behaves like prefer for postgres.js compatibility,
-                // allowing graceful fallback to non-SSL when the server
-                // doesn't support it.
-                SSLMode::Require | SSLMode::Prefer | SSLMode::Disable => {}
+                SSLMode::Prefer | SSLMode::Disable => {}
             }
         }
         // Send auth response
```