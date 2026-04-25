# SHA-384 Marked Non-Approved

## Classification

Logic error, medium severity, confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/tls12/tls12.go:62`

## Summary

`tls12.MasterSecret` incorrectly treats SHA-384 as non-approved because it checks for SHA-384 digest size `46` instead of the correct size `48`. Any TLS 1.2 master secret derivation using SHA-384 records a non-approved FIPS service indicator before the PRF runs.

## Provenance

Verified from local source review and reproducer analysis.

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

`MasterSecret` is called with `crypto/internal/fips140/sha512` SHA-384 digest.

## Proof

`MasterSecret` receives a caller-supplied hash constructor and evaluates:

- `h := hash()`
- `h` enters the `*sha512.Digest` case
- SHA-384 has `h.Size() == 48`
- The existing condition accepts only `46` or `64`
- Therefore SHA-384 falls through to `fips140.RecordNonApproved()`

`src/crypto/internal/fips140/indicator.go:58` shows `RecordNonApproved` forces the service indicator false, overriding later approved records from HMAC/SHA operations during the PRF.

This path is reachable through TLS 1.2 EMS with SHA-384 cipher suites:

- `src/crypto/tls/prf.go:95` selects `sha512.New384` for `suiteSHA384`
- `src/crypto/tls/prf.go:123` calls `tls12.MasterSecret(hash.New, ...)`
- `src/crypto/tls/defaults_fips140.go:53` allows SHA-384 TLS 1.2 suites such as `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`

## Why This Is A Real Bug

SHA-384 digest output size is 48 bytes. The code uses `46`, so valid SHA-384 TLS 1.2 KDF usage is always marked non-approved. FIPS policy allows the affected TLS 1.2 SHA-384 suites, so the service indicator behavior is incorrect.

## Fix Requirement

Change the accepted SHA-384 digest size from `46` to `48`.

## Patch Rationale

The patch corrects the constant used to identify approved SHA-384 in the `*sha512.Digest` branch. SHA-512 remains accepted at size `64`, and unsupported SHA-512-family digest sizes still record non-approved.

## Residual Risk

None

## Patch

Patch file: `050-sha-384-marked-non-approved.patch`

```diff
diff --git a/src/crypto/internal/fips140/tls12/tls12.go b/src/crypto/internal/fips140/tls12/tls12.go
--- a/src/crypto/internal/fips140/tls12/tls12.go
+++ b/src/crypto/internal/fips140/tls12/tls12.go
@@ -59,7 +59,7 @@ func MasterSecret[Hash fips140.Hash](hash func() Hash, preMasterSecret, clientR
 	case *sha256.Digest:
 		tlsapproved = true
 	case *sha512.Digest:
-		tlsapproved = h.Size() == 46 || h.Size() == 64
+		tlsapproved = h.Size() == 48 || h.Size() == 64
 	}
 	if !tlsapproved {
 		fips140.RecordNonApproved()
```