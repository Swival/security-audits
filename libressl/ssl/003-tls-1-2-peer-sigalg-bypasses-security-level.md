# TLS 1.2 Peer Sigalg Bypasses Security Level

## Classification

Policy bypass, medium severity, certain confidence.

## Affected Locations

`ssl_sigalgs.c:293`

## Summary

TLS 1.2 peer-provided signature algorithm values were accepted without enforcing the configured OpenSSL security level against the selected signature algorithm. As a result, a malicious peer could choose SHA1-based TLS 1.2 handshake signatures and have them verified even when the local endpoint configured security level 2 or higher.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- TLS 1.2 signature algorithms are enabled.
- Local security level is above 1.
- Peer has a matching RSA or EC certificate/key accepted by the existing key checks.
- Peer controls the TLS 1.2 `signature_algorithm` value in the relevant handshake message.

## Proof

`ssl_sigalg_for_peer()` receives the peer-controlled `sigalg_value` and resolves it through `ssl_sigalg_from_value()`.

For TLS 1.2, `tls12_sigalgs` includes:

- `SIGALG_RSA_PKCS1_SHA1`
- `SIGALG_ECDSA_SHA1`

Both map to `sigalgs[]` entries with:

- `.md = EVP_sha1`
- `.security_level = 1`

Before the patch, `ssl_sigalg_for_peer()` accepted the resolved algorithm if `ssl_sigalg_pkey_ok()` returned true. That helper checked:

- non-null `sigalg` and `pkey`
- matching key type
- RSA-PSS size constraints
- `ssl_security_sigalg_check(s, pkey)`
- TLS 1.3 RSA-PSS restrictions
- TLS 1.3 EC group matching

It did not compare `sigalg->security_level` with `SSL_get_security_level(s)`.

The accepted algorithm is then used directly for signature verification:

- Client-side ServerKeyExchange verification reads the peer-controlled value at `ssl_clnt.c:1387`, accepts it via `ssl_sigalg_for_peer()` at `ssl_clnt.c:1399`, and verifies with `sigalg->md()` at `ssl_clnt.c:1406`.
- Server-side client CertificateVerify follows the same pattern at `ssl_srvr.c:1935`, `ssl_srvr.c:1953`, and `ssl_srvr.c:1968`.

This allows a malicious TLS 1.2 peer to send a SHA1 handshake signature and complete verification despite a configured security level that should reject SHA1.

## Why This Is A Real Bug

The library already enforces this policy elsewhere:

- Outbound signature algorithm lists skip algorithms where `sigalg->security_level < security_level` in `ssl_sigalgs_build()` at `ssl_sigalgs.c:245`.
- Legacy SHA1 defaults are rejected above security level 1 in `ssl_sigalg_for_legacy()` at `ssl_sigalgs.c:259`.

Peer-selected TLS 1.2 signature algorithms should be subject to the same security-level policy. Without this check, the local endpoint may verify and accept a signature algorithm it would not advertise or select itself.

## Fix Requirement

Reject any resolved peer signature algorithm where:

```c
sigalg->security_level < SSL_get_security_level(s)
```

before returning or using the algorithm for handshake signature verification.

## Patch Rationale

The patch adds the security-level comparison inside `ssl_sigalg_pkey_ok()`:

```diff
+	if (sigalg->security_level < SSL_get_security_level(s))
+		return 0;
+
```

This is the correct enforcement point because both peer-selected and locally selected signature algorithm paths already use `ssl_sigalg_pkey_ok()` to validate algorithm/key compatibility. Placing the check there centralizes the policy and prevents SHA1 TLS 1.2 peer signature algorithms from passing when the configured security level is above 1.

## Residual Risk

None

## Patch

```diff
diff --git a/ssl_sigalgs.c b/ssl_sigalgs.c
index ee4088f..ebe9ee0 100644
--- a/ssl_sigalgs.c
+++ b/ssl_sigalgs.c
@@ -278,6 +278,9 @@ ssl_sigalg_pkey_ok(SSL *s, const struct ssl_sigalg *sigalg, EVP_PKEY *pkey)
 	if (sigalg == NULL || pkey == NULL)
 		return 0;
 
+	if (sigalg->security_level < SSL_get_security_level(s))
+		return 0;
+
 	if (sigalg->key_type != EVP_PKEY_id(pkey))
 		return 0;
```