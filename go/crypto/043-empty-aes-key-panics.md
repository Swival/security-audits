# Empty AES Key Panics

## Classification

Error-handling bug, low severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/boring/aes.go:84`

## Summary

`NewAESCipher` indexes `c.key[0]` before validating that the caller-provided key is non-empty. When `key` is empty, this causes a Go runtime panic instead of returning the expected `aesKeySizeError`.

## Provenance

Verified from the supplied finding and reproducer. Originally reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller passes an empty key to `crypto/internal/boring.NewAESCipher` under the BoringCrypto build configuration:

`boringcrypto && linux && (amd64 || arm64) && !android && !msan`

## Proof

`NewAESCipher` clones the caller-controlled key into `c.key`.

For `key := []byte{}`, `bytes.Clone(key)` produces a zero-length slice. The function then evaluates:

```go
unsafe.Pointer(&c.key[0])
```

before calling BoringCrypto key setup. Because `c.key` has length zero, `c.key[0]` panics with:

```text
runtime error: index out of range [0] with length 0
```

The panic occurs before `_goboringcrypto_AES_set_decrypt_key` or `_goboringcrypto_AES_set_encrypt_key` can reject the invalid key and return a key-size error.

## Why This Is A Real Bug

The function’s error path is bypassed by an unchecked slice index. Invalid key sizes are supposed to be reported as `aesKeySizeError`, but an empty key instead terminates control flow with a panic.

The public `crypto/aes.NewCipher` wrapper validates key length first, so the panic is not exposed through that API. However, `crypto/internal/boring.NewAESCipher` is directly reachable from code permitted to import the internal package, making the bug real within its supported caller set.

## Fix Requirement

Check `len(key) == 0` before taking `&c.key[0]`, and return `aesKeySizeError` for the empty-key case.

## Patch Rationale

The patch adds an explicit empty-key guard before `c.key[0]` is evaluated. This preserves existing behavior for valid keys and converts the panic path into the same structured error used for invalid AES key sizes.

## Residual Risk

None

## Patch

Patch file: `043-empty-aes-key-panics.patch`

The patch implements the required pre-index length check in `src/crypto/internal/boring/aes.go`, returning `aesKeySizeError` when `NewAESCipher` receives an empty key.