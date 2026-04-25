# NULL Policy Failure Reports Success Status

## Classification

Error-handling bug. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/x509/internal/macos/security.go:75`

## Summary

`SecPolicyCreateSSL` treats a NULL Security framework return as failure, but reports it as `OSStatus` code `0`. Since `0` conventionally means success, diagnostics falsely present policy creation failure as a successful OSStatus.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

`SecPolicyCreateSSL` returns NULL on darwin.

## Proof

Hostname input reaches `SecPolicyCreateSSL` through certificate verification. The wrapper calls the Security framework and stores the returned CF reference in `ret`.

On NULL, `ret == 0`. The failure path constructs:

`OSStatus{"SecPolicyCreateSSL", int32(ret)}`

Because `ret` is zero, `Error()` renders an OSStatus success value, e.g. `SecPolicyCreateSSL error: 0`, even though the wrapper is returning a non-nil error for a failed NULL policy reference.

## Why This Is A Real Bug

The Go operation does not incorrectly succeed because the returned error is non-nil. However, the error value misclassifies the failure as OSStatus `0`, which is misleading and can break diagnostics or error handling that relies on OSStatus semantics.

The bug is reachable whenever Security framework policy creation/allocation returns NULL.

## Fix Requirement

Do not report NULL policy creation as `OSStatus(0)`. Return a non-OSStatus error or an explicit invalid policy creation failure when `SecPolicyCreateSSL` returns NULL.

## Patch Rationale

The patch changes the NULL return path to report an explicit policy creation failure instead of converting the NULL CF reference value to an OSStatus. This preserves the existing non-nil error behavior while removing the misleading success-status diagnostic.

## Residual Risk

None

## Patch

`018-null-policy-failure-reports-success-status.patch`