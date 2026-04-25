# Zero hash panic in PKCS#1 v1.5 FIPS approval path

## Classification
- Type: error-handling bug
- Severity: Medium
- Confidence: Certain

## Affected Locations
- `src/crypto/rsa/fips.go:342`
- `src/crypto/rsa/fips.go:388`
- Originally observed at `src/crypto/rsa/fips.go:308`

## Summary
`rsa.SignPKCS1v15` and `rsa.VerifyPKCS1v15` both document and accept `hash == crypto.Hash(0)` to mean "use the input directly." In FIPS 140-only mode, both functions instead reached a FIPS approval check that evaluated `hash.New()` unconditionally. For `crypto.Hash(0)`, `hash.New()` panics, so attacker-controlled input causes process termination rather than a normal rejected-operation error.

## Provenance
- Verified finding reproduced from Swival Security Scanner: https://swival.dev
- Reproducer confirmed panic under FIPS-only enforcement and identified the same reachable bug in both sign and verify paths.

## Preconditions
- FIPS 140-only mode is enabled
- Caller supplies `hash == crypto.Hash(0)`
- Code path reaches `rsa.SignPKCS1v15` or `rsa.VerifyPKCS1v15`
- A FIPS-acceptable RSA key is used so execution reaches the hash approval check

## Proof
`SignPKCS1v15` allows zero hash:
```go
if hash != crypto.Hash(0) {
    if len(hashed) != hash.Size() {
        return nil, errors.New("crypto/rsa: input must be hashed message")
    }
    hashName = hash.String()
}
```

But in FIPS-only mode it previously did:
```go
if fips140only.Enforced() && !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New())) {
    return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
}
```

`crypto.Hash(0).New()` panics. The reproducer established:
- FIPS-only mode is a normal runtime configuration via `GODEBUG=fips140=only`
- The panic is reachable through caller-controlled `hash`
- The same pattern exists in `VerifyPKCS1v15`

Patched condition:
```go
if fips140only.Enforced() && (hash == crypto.Hash(0) || !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New()))) {
    return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
}
```

Equivalent logic was applied to `VerifyPKCS1v15`.

## Why This Is A Real Bug
This is a reachable denial of service in a supported configuration. The API contract explicitly permits `hash == 0`, so callers can legally pass it. FIPS-only mode then transforms that valid API input into an unconditional panic before cryptographic processing. The expected behavior is policy rejection with an error, not process crash. Because FIPS-only mode is enabled at runtime and the input is caller-controlled, this is not theoretical.

## Fix Requirement
Reject `hash == crypto.Hash(0)` before any `hash.New()` call in the FIPS approval path and return the existing FIPS-mode hash restriction error instead of panicking. Apply the same guard to both PKCS#1 v1.5 sign and verify.

## Patch Rationale
The patch adds an explicit zero-hash check into each FIPS-only conditional. This preserves non-FIPS behavior, preserves existing FIPS rejection text, and prevents evaluation of `hash.New()` on an invalid hash identifier. The change is narrowly scoped to the two vulnerable call sites.

## Residual Risk
None

## Patch
```diff
diff --git a/src/crypto/rsa/fips.go b/src/crypto/rsa/fips.go
index fb2395886b..09fdf6c244 100644
--- a/src/crypto/rsa/fips.go
+++ b/src/crypto/rsa/fips.go
@@ -342,7 +342,7 @@ func SignPKCS1v15(random io.Reader, priv *PrivateKey, hash crypto.Hash, hashed [
 	if err := checkFIPS140OnlyPrivateKey(priv); err != nil {
 		return nil, err
 	}
-	if fips140only.Enforced() && !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New())) {
+	if fips140only.Enforced() && (hash == crypto.Hash(0) || !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New()))) {
 		return nil, errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
 	}
 
@@ -388,7 +388,7 @@ func VerifyPKCS1v15(pub *PublicKey, hash crypto.Hash, hashed []byte, sig []byte)
 	if err := checkFIPS140OnlyPublicKey(pub); err != nil {
 		return err
 	}
-	if fips140only.Enforced() && !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New())) {
+	if fips140only.Enforced() && (hash == crypto.Hash(0) || !fips140only.ApprovedHash(fips140hash.Unwrap(hash.New()))) {
 		return errors.New("crypto/rsa: use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS 140-only mode")
 	}
```