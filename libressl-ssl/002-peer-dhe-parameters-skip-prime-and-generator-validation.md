# Peer DHE Parameters Skip Prime And Generator Validation

## Classification

security_control_failure, high severity, confirmed.

## Affected Locations

`ssl_kex.c:148`

## Summary

`ssl_kex_peer_params_dhe()` accepts peer-controlled TLS DHE parameters after decoding and installing `p` and `g`, but only rejects groups smaller than `DHE_MINIMUM_BITS`. It does not validate that `p` is prime or that `g` is a suitable generator, so malicious peers can supply invalid DH groups with at least 1024 bits and have them enter DHE key derivation.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

Confidence: certain.

## Preconditions

A malicious TLS peer supplies DHE parameters where `DH_bits(dh) >= 1024`.

## Proof

`ssl_kex_peer_params_dhe()` parses peer-controlled `p` and `g` using `BN_bin2bn()`, installs them with `DH_set0_pqg()`, and then only marks parameters invalid when `DH_bits(dh) < DHE_MINIMUM_BITS`.

Reproduction confirmed:

- A 1024-bit composite `p = 2^1023 + 1` with `g = 2` was accepted with `ret = 1` and `invalid_params = 0`.
- `DH_check()` flagged the same group with `DH_CHECK_P_NOT_PRIME`.
- Key generation and `DH_compute_key()` still succeeded with the invalid group.
- A valid 1024-bit prime with invalid `g = 0` was also accepted with `ret = 1` and `invalid_params = 0`.
- `DH_check()` flagged the invalid-generator case as unsuitable.
- Later checks do not fix this: `ssl_kex.c:226` checks only the peer public key, and `tls_key_share.c:799` uses `DH_security_bits`, not primality or generator validity.
- Accepted parameters are duplicated into the key share at `tls_key_share.c:462` and can enter DHE key generation and derivation through `ssl_clnt.c:1869`, `ssl_clnt.c:1873`, and `tls_key_share.c:668`.

## Why This Is A Real Bug

TLS DHE parameter validation must reject invalid DH groups before use. The current implementation has an explicit validation gap: it even contains `/* XXX - consider calling DH_check(). */`, then proceeds with only a bit-length check.

Because peer-supplied composite primes and unsuitable generators can be accepted and later used for key derivation, the validation control fails open. Public-key validation and security-bit checks are insufficient substitutes because they do not establish that `p` is prime or that `g` is valid for the group.

## Fix Requirement

Call `DH_check()` after `DH_set0_pqg()` and reject any nonzero `DH_CHECK_*` flags before accepting peer DHE parameters.

The existing minimum-size rejection must remain in place.

## Patch Rationale

The patch adds `DH_check(dh, &check_flags)` in `ssl_kex_peer_params_dhe()` after the peer-supplied parameters are installed. If `DH_check()` fails, parsing fails. If `DH_check()` succeeds but reports any validation flags, `invalid_params` is set.

This aligns DHE parameter handling with the required validation boundary: decoded peer parameters are accepted only if OpenSSL’s DH validation reports no prime, generator, or parameter defects, and the group still satisfies the existing minimum-bit policy.

## Residual Risk

None

## Patch

```diff
diff --git a/ssl_kex.c b/ssl_kex.c
index fa420a3..9cca656 100644
--- a/ssl_kex.c
+++ b/ssl_kex.c
@@ -160,6 +160,7 @@ ssl_kex_peer_params_dhe(DH *dh, CBS *cbs, int *decode_error,
 {
 	BIGNUM *p = NULL, *g = NULL;
 	CBS dh_p, dh_g;
+	int check_flags;
 	int ret = 0;
 
 	*decode_error = 0;
@@ -184,9 +185,9 @@ ssl_kex_peer_params_dhe(DH *dh, CBS *cbs, int *decode_error,
 	p = NULL;
 	g = NULL;
 
-	/* XXX - consider calling DH_check(). */
-
-	if (DH_bits(dh) < DHE_MINIMUM_BITS)
+	if (!DH_check(dh, &check_flags))
+		goto err;
+	if (check_flags != 0 || DH_bits(dh) < DHE_MINIMUM_BITS)
 		*invalid_params = 1;
 
 	ret = 1;
```