# Negative EKM Length Panics

## Classification

Validation gap; low severity; confidence: certain.

## Affected Locations

`src/crypto/tls/prf.go:52`

## Summary

TLS 1.0/1.1 exported keying material generation accepts a caller-supplied `length` parameter and passes it unchecked into the legacy PRF. When `length` is negative, `prf10` executes `make([]byte, keyLen)`, which panics at runtime instead of returning an error.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

- A TLS 1.0 or TLS 1.1 connection is established.
- EKM is available to the caller, such as with EMS negotiated or `GODEBUG=tlsunsafeekm=1` for legacy non-EMS sessions.
- The local caller invokes the exported keying material function with a negative `length`.

## Proof

- `ConnectionState.ExportKeyingMaterial` delegates to the caller-facing EKM function.
- TLS 1.0/1.1 handshakes set `c.ekm` from `ekmFromMasterSecret`.
- `ekmFromMasterSecret` validates reserved labels and context length but does not reject negative `length`.
- It then calls `prfForVersion(version, suite)(..., length)`.
- For `VersionTLS10` and `VersionTLS11`, `prfForVersion` selects `prf10`.
- `prf10` immediately executes `make([]byte, keyLen)`.
- In Go, `make([]byte, -1)` panics with `len out of range`.

## Why This Is A Real Bug

The affected API is caller-facing and already returns errors for invalid EKM inputs. A negative length is invalid input, but on TLS 1.0/1.1 it reaches an allocation before validation and crashes the goroutine/process path. This is inconsistent with the surrounding validation behavior and allows a local API misuse path to become a runtime panic instead of a handled error.

## Fix Requirement

Reject negative EKM lengths in `ekmFromMasterSecret` before invoking the PRF.

## Patch Rationale

The patch adds an explicit `length < 0` check at the EKM validation boundary. This prevents negative values from reaching `prf10`, preserves existing behavior for valid non-negative lengths, and converts the panic into a normal returned error.

## Residual Risk

None

## Patch

`053-negative-ekm-length-panics.patch`