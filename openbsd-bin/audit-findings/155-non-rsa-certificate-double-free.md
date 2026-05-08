# Non-RSA Certificate Double Free

## Classification

Memory corruption, high severity.

## Affected Locations

`sbin/isakmpd/x509.c:1170`

Primary failing ownership violation:

`sbin/isakmpd/x509.c:1287`

Caller-side second free:

`sbin/isakmpd/x509.c:1175`

Additional reproduced caller path:

`sbin/isakmpd/ike_auth.c:702`

`sbin/isakmpd/ike_auth.c:703`

`sbin/isakmpd/x509.c:956`

`sbin/isakmpd/x509.c:962`

## Summary

A remote IKE peer can provide a CA-valid X.509 certificate with a non-RSA public key. The certificate is accepted by validation, then reaches RSA-specific KeyNote policy generation. `x509_cert_get_key()` detects the non-RSA key, frees the caller-owned `X509 *cert`, and returns failure. Its caller then frees the same certificate again on the failure path, causing a double free in `isakmpd`.

## Provenance

Verified and reproduced from Swival Security Scanner findings: https://swival.dev

Confidence: certain.

## Preconditions

- RSA-signature IKE authentication is in use.
- Peer sends an X.509 certificate with a non-RSA public key, such as EC or DSA.
- The certificate chain validates successfully against configured trust anchors.
- The certificate identity matches the peer ID payload.
- The peer certificate is inserted after parsing.

## Proof

`x509_cert_insert()` duplicates the peer certificate with `X509_dup()` and passes the duplicate to `x509_generate_kn()`.

`x509_generate_kn()` immediately calls `x509_cert_get_key(cert, &key)` to extract an RSA public key for KeyNote policy generation.

For a non-RSA key, `x509_cert_get_key()` executes:

```c
if (EVP_PKEY_id(key) != EVP_PKEY_RSA) {
	log_print("x509_cert_get_key: public key is not a RSA key");
	X509_free(cert);
	return 0;
}
```

This frees `cert` even though the function does not own it. The failure propagates back to `x509_cert_insert()`, which then executes its own cleanup:

```c
if (x509_generate_kn(id, cert) == 0) {
	LOG_DBG((LOG_POLICY, 50,
	    "x509_cert_insert: x509_generate_kn failed"));
	X509_free(cert);
	return 0;
}
```

The same `X509 *cert` is therefore freed twice.

The reproduced authentication path also reaches the same ownership violation: `x509_cert_get_key()` frees the caller-owned certificate, then `handler->cert_free(cert)` maps to `x509_cert_free()`, which calls `X509_free()` again.

## Why This Is A Real Bug

Certificate validation does not require an RSA leaf key. A CA-valid non-RSA peer certificate can pass `x509_cert_validate()` and reach key extraction. The second free occurs before signature verification completes, so the attacker does not need to complete authentication. The practical impact is remote denial of service and possible allocator memory corruption in `isakmpd`.

## Fix Requirement

`x509_cert_get_key()` must not free `scert` on failure. Ownership of the `X509 *` remains with the caller in all success and failure cases.

## Patch Rationale

The patch removes the incorrect `X509_free(cert)` from the non-RSA failure path. This restores consistent ownership semantics: `x509_cert_get_key()` only inspects the certificate and returns an RSA key duplicate through `keyp`; callers remain responsible for freeing their own certificate objects.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/isakmpd/x509.c b/sbin/isakmpd/x509.c
index 7ebe09d..a6783f8 100644
--- a/sbin/isakmpd/x509.c
+++ b/sbin/isakmpd/x509.c
@@ -1284,7 +1284,6 @@ x509_cert_get_key(void *scert, void *keyp)
 	/* Check if we got the right key type.  */
 	if (EVP_PKEY_id(key) != EVP_PKEY_RSA) {
 		log_print("x509_cert_get_key: public key is not a RSA key");
-		X509_free(cert);
 		return 0;
 	}
 	*(RSA **)keyp = RSAPublicKey_dup(EVP_PKEY_get0_RSA(key));
```