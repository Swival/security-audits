# Server-Chosen RSA Key Receives Password Encryption

## Classification

High severity information disclosure.

## Affected Locations

`src/sql/mysql/protocol/Auth.rs:222`

`src/sql/mysql/protocol/Auth.rs:230`

`src/sql/mysql/protocol/Auth.rs:274`

`src/sql/mysql/protocol/Auth.rs:316`

`src/sql_jsc/mysql/MySQLConnection.rs:721`

`src/sql_jsc/mysql/MySQLConnection.rs:726`

`src/sql_jsc/mysql/MySQLConnection.rs:818`

## Summary

During `caching_sha2_password` RSA fallback, the client accepted an unauthenticated RSA public key from the server and encrypted the password-derived plaintext with it. A malicious MySQL server or active MITM could supply its own public key, receive the encrypted password packet, and decrypt it using the matching private key.

The patch disables this unsafe plaintext-TCP RSA fallback by failing authentication when `caching_sha2_password` requests continuation while `ssl_mode == SSLMode::Disable`.

## Provenance

Verified and reproduced from scanner output.

Source: Swival.dev Security Scanner, https://swival.dev

Confidence: certain.

## Preconditions

- Client authenticates with MySQL `caching_sha2_password`.
- Server requests RSA password fallback.
- Connection is not protected by TLS.
- Attacker controls the MySQL server or can act as an active MITM.

## Proof

`caching_sha2_password::PublicKeyResponse::decode_internal` reads all remaining response bytes into `response.data` without authentication at `src/sql/mysql/protocol/Auth.rs:316`.

The connection code then passes this untrusted data directly as `EncryptedPassword.public_key` at `src/sql_jsc/mysql/MySQLConnection.rs:726`.

`EncryptedPassword::write_internal` constructs `plain_password` from `password || "\0"` and XORs it with the server nonce at `src/sql/mysql/protocol/Auth.rs:203`.

It parses the supplied PEM key using `PEM_read_bio_RSA_PUBKEY` at `src/sql/mysql/protocol/Auth.rs:230`.

It then encrypts the password-derived plaintext with `RSA_public_encrypt` at `src/sql/mysql/protocol/Auth.rs:274`.

Because the attacker supplies the public key and controls or observes the nonce, the attacker can decrypt the returned password packet with the matching private key and recover the plaintext database password.

## Why This Is A Real Bug

The RSA public key used for password encryption is security-critical authentication material. In the vulnerable flow, that key is selected by the peer over an unauthenticated non-TLS channel.

RSA encryption only protects the password from observers who do not possess the private key. If a malicious server or MITM chooses the RSA key, it necessarily has the private key and can decrypt the password packet. This makes the fallback equivalent to disclosing the plaintext password to the attacker.

## Fix Requirement

Do not encrypt the password to an unauthenticated server-provided RSA key.

Acceptable fixes are:

- Require TLS before sending the password.
- Verify or pin the server RSA public key before encryption.

## Patch Rationale

The patch changes `src/sql_jsc/mysql/MySQLConnection.rs:818` so that when `caching_sha2_password` requires continued authentication and `ssl_mode == SSLMode::Disable`, authentication fails immediately with `AnyMySQLError::AuthenticationFailed`.

This removes the vulnerable branch that previously:

- Entered `AuthenticationAwaitingPk`.
- Requested a public key from the server.
- Accepted the server response as the RSA key.
- Encrypted the password to that unauthenticated key.

TLS-enabled authentication remains available, preserving the safe path where the password exchange is protected by the transport.

## Residual Risk

None

## Patch

```diff
diff --git a/src/sql_jsc/mysql/MySQLConnection.rs b/src/sql_jsc/mysql/MySQLConnection.rs
index 77382ca441..633253b7ba 100644
--- a/src/sql_jsc/mysql/MySQLConnection.rs
+++ b/src/sql_jsc/mysql/MySQLConnection.rs
@@ -818,18 +818,7 @@ impl MySQLConnection {
                                     bun_core::scoped_log!(MySQLConnection, "continue auth");
 
                                     if self.ssl_mode == SSLMode::Disable {
-                                        // we are in plain TCP so we need to request the public key
-                                        self.set_status(ConnectionState::AuthenticationAwaitingPk);
-                                        bun_core::scoped_log!(
-                                            MySQLConnection,
-                                            "awaiting public key"
-                                        );
-                                        let mut packet = self.writer().start(self.sequence_id)?;
-
-                                        let request = Auth::caching_sha2_password::PublicKeyRequest;
-                                        request.write(self.writer())?;
-                                        packet.end()?;
-                                        self.flush_data();
+                                        return Err(AnyMySQLError::AuthenticationFailed);
                                     } else {
                                         bun_core::scoped_log!(
                                             MySQLConnection,
```