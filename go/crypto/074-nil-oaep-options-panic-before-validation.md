# Nil `OAEPOptions` panic before validation

## Classification
- Type: validation gap
- Severity: medium
- Confidence: certain

## Affected Locations
- `src/crypto/rsa/fips.go:203`
- `src/crypto/rsa/fips.go:206`

## Summary
`EncryptOAEPWithOptions` accepted a caller-controlled `*OAEPOptions` and dereferenced it immediately without a nil check. Passing `nil` caused a panic before any normal validation or error handling, turning malformed API input into a process crash.

## Provenance
- Verified finding reproduced from the provided source and reproducer notes
- Scanner source: [Swival Security Scanner](https://swival.dev)

## Preconditions
- A caller can invoke `EncryptOAEPWithOptions` with `nil` for `opts`.

## Proof
`EncryptOAEPWithOptions` is exported and takes `opts *OAEPOptions`. In the vulnerable code path it immediately evaluated `opts.MGFHash`, then `opts.Hash.New()` and `opts.Label`, with the first dereference at `src/crypto/rsa/fips.go:206`. Because `OAEPOptions` is an exported struct type, a caller can directly pass a typed nil pointer such as `rsa.EncryptOAEPWithOptions(rand.Reader, pub, msg, nil)`. No guard existed before those dereferences, so the function panicked before reaching `encryptOAEP` or any key/hash validation.

## Why This Is A Real Bug
This is a direct denial-of-service condition on an exported API. The trigger is simple, deterministic, and requires no unusual runtime state: a nil pointer argument causes an immediate panic instead of a returned error. The surrounding package already shows that nil option handling is expected to be explicit, such as `PSSOptions.saltLength()` tolerating nil and `PrivateKey.Decrypt` checking nil options up front. That makes the missing check here a concrete input-validation defect, not just misuse.

## Fix Requirement
Add an early `opts == nil` check in `EncryptOAEPWithOptions` and return a regular error rather than dereferencing the pointer. This prevents panic-based termination on malformed input.

## Patch Rationale
The patch inserts a guard at function entry:
- `if opts == nil { return nil, errors.New("crypto/rsa: missing OAEPOptions") }`

This is the narrowest safe fix. It preserves existing behavior for valid callers, blocks the nil dereference before any field access, and converts the crash into standard API error handling.

## Residual Risk
None

## Patch
```diff
diff --git a/src/crypto/rsa/fips.go b/src/crypto/rsa/fips.go
index fb2395886b..77e5e7aebf 100644
--- a/src/crypto/rsa/fips.go
+++ b/src/crypto/rsa/fips.go
@@ -203,6 +203,9 @@ func EncryptOAEP(hash hash.Hash, random io.Reader, pub *PublicKey, msg []byte, l
 //
 // See [EncryptOAEP] for additional details.
 func EncryptOAEPWithOptions(random io.Reader, pub *PublicKey, msg []byte, opts *OAEPOptions) ([]byte, error) {
+	if opts == nil {
+		return nil, errors.New("crypto/rsa: missing OAEPOptions")
+	}
 	if opts.MGFHash == 0 {
 		return encryptOAEP(opts.Hash.New(), opts.Hash.New(), random, pub, msg, opts.Label)
 	}
```