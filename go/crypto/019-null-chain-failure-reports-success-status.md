# NULL Chain Failure Reports Success Status

## Classification

Error-handling bug, low severity. Confidence: certain.

## Affected Locations

`src/crypto/x509/internal/macos/security.go:132`

## Summary

`SecTrustCopyCertificateChain` returns a Core Foundation object pointer, but the wrapper treated a NULL return as an `OSStatus` failure using the returned pointer value. When the syscall returned `0`, the error became `OSStatus{"SecTrustCopyCertificateChain", 0}`, causing a non-nil failure to report status code `0`, which conventionally means success.

## Provenance

Found by Swival Security Scanner: https://swival.dev

## Preconditions

- `SecTrustCopyCertificateChain` syscall returns NULL for a trust object.
- The wrapper reaches the `ret == 0` failure branch.

## Proof

The caller-supplied `trustObj` is passed directly to `x509_SecTrustCopyCertificateChain_trampoline`.

When the syscall returns `0`, the wrapper enters the failure branch at `src/crypto/x509/internal/macos/security.go:142`, but constructs:

```go
OSStatus{"SecTrustCopyCertificateChain", int32(ret)}
```

Since `ret == 0`, `OSStatus.Error()` formats the failure as:

```text
SecTrustCopyCertificateChain error: 0
```

That violates the invariant that a NULL object-return failure must not be represented as a success `OSStatus`.

The error propagates through `systemVerify` at `src/crypto/x509/root_darwin.go:76` and is returned directly at `src/crypto/x509/root_darwin.go:77`.

## Why This Is A Real Bug

`SecTrustCopyCertificateChain` returns a CF object pointer, not an `OSStatus`. A NULL pointer indicates failure, but the pointer value itself is not an OSStatus code.

Returning `OSStatus` with code `0` creates a misleading non-nil error that reports success. This does not cause certificate verification to succeed, but it obscures the real failure cause and can mislead diagnostics or caller error handling.

## Fix Requirement

Return a descriptive non-`OSStatus` error when `SecTrustCopyCertificateChain` returns NULL.

## Patch Rationale

The patch replaces the misleading `OSStatus{"SecTrustCopyCertificateChain", int32(ret)}` construction with a descriptive error for the NULL-return case.

This preserves failure behavior while avoiding an impossible success-status error report.

## Residual Risk

None

## Patch

`019-null-chain-failure-reports-success-status.patch`