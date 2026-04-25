# Short RandNonce Ciphertext Panics

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140test/acvp_test.go:1488`

## Summary

`cmdAesGcmOpen` in the randNonce path slices a 12-byte nonce from the end of the ciphertext without checking that the ciphertext is at least 12 bytes long. A short ciphertext causes a panic from negative slice bounds.

## Provenance

Inferred from the provided patch. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

- The ACVP wrapper receives a randNonce AES-GCM open request.
- The ciphertext argument is shorter than 12 bytes.

## Proof

For randNonce tests, acvptool appends a 12-byte nonce to the end of the ciphertext. The handler splits them with:

```go
nonce = ciphertext[len(ciphertext)-12:]
ciphertext = ciphertext[:len(ciphertext)-12]
```

When `len(ciphertext) < 12`, the expression `len(ciphertext)-12` is negative, causing:

```text
panic: runtime error: slice bounds out of range
```

The wrapper process terminates instead of returning a decryption failure.

## Why This Is A Real Bug

The ciphertext is externally supplied input parsed by `readRequest`. The handler accepts the request and reaches the vulnerable slice operation without validating that the ciphertext is long enough to contain the appended nonce.

## Fix Requirement

Check `len(ciphertext) < 12` before slicing the nonce, and return a decryption failure for short inputs.

## Patch Rationale

The patch adds an explicit length check before the slice operation. Short ciphertexts are handled as decryption failures rather than allowing a runtime panic.

## Residual Risk

None

## Patch

`002-short-randnonce-ciphertext-panics.patch`
