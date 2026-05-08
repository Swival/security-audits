# Zero-Length Bundle Certificate Becomes Bogus X509 Pointer

## Classification

Denial of service, high severity, remote attacker-triggered crash.

Confidence: certain.

## Affected Locations

`sbin/iked/ca.c:1786`

## Summary

`ca_decode_cert_bundle()` accepted a zero-length certificate entry in an `IKEV2_CERT_BUNDLE`. When the first bundle entry had `datalen == 0`, the decoder returned success with `*datap` pointing into attacker-controlled bundle bytes and `*lenp == 0`. `ca_getcert()` then converted the bundle type to `IKEV2_CERT_X509_CERT` and passed that pointer and zero length into `ca_validate_cert()`. `ca_validate_cert()` interprets `len == 0` as meaning the input is already an `X509 *`, casts the attacker-controlled pointer to `X509 *`, and dereferences it through OpenSSL, crashing the CA process.

## Provenance

Verified from supplied source, reproducer summary, and patch.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

A remote peer can reach IKE certificate authentication handling.

## Proof

A practical trigger is:

1. A remote IKE peer reaches certificate-authentication handling.
2. The peer sends `AUTH`.
3. The peer sends a first X.509 certificate bundle entry with zero certificate bytes.
4. The peer sends a second parseable X.509 certificate entry so the bundle decoder succeeds.

Observed vulnerable flow:

- `ca_decode_cert_bundle()` permits `datalen == 0` for the first entry, sets `certdata = ptr`, sets `certlen = datalen`, and returns success.
- `ca_getcert()` changes the internal type from `IKEV2_CERT_BUNDLE` to `IKEV2_CERT_X509_CERT`.
- `ca_getcert()` calls `ca_validate_cert(env, &id, ptr, len, untrusted, ...)` with attacker-derived `ptr` and `len == 0`.
- `ca_validate_cert()` treats `len == 0` as “data is already an X509 certificate”, casts `data` to `X509 *`, and calls `X509_get_subject_name(cert)`.
- OpenSSL dereferences a bogus `X509 *`, crashing the CA process.

The reproducer was confirmed as `REPRODUCED`.

## Why This Is A Real Bug

The zero-length first bundle entry crosses an internal API boundary where zero length has special meaning. In bundle decoding, zero length means an empty peer-supplied certificate. In `ca_validate_cert()`, zero length means the caller supplied an already-decoded trusted in-memory `X509 *`. Because `ca_getcert()` forwards attacker-controlled bundle storage with `len == 0`, untrusted bytes are reinterpreted as a live OpenSSL object pointer. That is memory-unsafe behavior reachable by a remote IKE peer and can terminate the CA process, causing denial of service.

## Fix Requirement

Reject zero-length certificate entries before they can be returned by `ca_decode_cert_bundle()` or passed to `ca_validate_cert()`.

## Patch Rationale

The patch adds an explicit `datalen == 0` check immediately after reading the bundle entry length and before accepting the value. This rejects empty certificate entries uniformly, including the first certificate entry that previously became `certdata` with `certlen == 0`. Failed decoding keeps the message on the invalid-certificate path instead of allowing `ca_validate_cert()` to reinterpret attacker-controlled data as an `X509 *`.

## Residual Risk

None

## Patch

```diff
diff --git a/sbin/iked/ca.c b/sbin/iked/ca.c
index b6175ea..d7da572 100644
--- a/sbin/iked/ca.c
+++ b/sbin/iked/ca.c
@@ -280,6 +280,11 @@ ca_decode_cert_bundle(struct iked *env, struct iked_sahdr *sh,
 		len -= sizeof(datalen);
 
 		/* Value */
+		if (datalen == 0) {
+			log_info("%s: zero-length certificate",
+			    SPI_SH(sh, __func__));
+			goto done;
+		}
 		if (len < datalen) {
 			log_info("%s: short len %zu < datalen %zu",
 			    SPI_SH(sh, __func__), len, datalen);
```