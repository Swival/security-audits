# Negative HKDF Length Panics

## Classification

Validation gap. Severity: low. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/hkdf/hkdf.go:28`

Also reachable through public wrappers in:

`src/crypto/hkdf/hkdf.go:48`

`src/crypto/hkdf/hkdf.go:65`

## Summary

A caller-controlled negative HKDF output length reaches `make([]byte, 0, keyLen)` before validation. Go panics with `runtime error: makeslice: cap out of range`, causing caller-triggered denial of service instead of returning an error.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller passes a negative `keyLen` / `keyLength` to HKDF `Expand` or `Key`.

## Proof

`src/crypto/internal/fips140/hkdf/hkdf.go:28` allocates with `make([]byte, 0, keyLen)` before checking whether `keyLen` is negative.

`src/crypto/internal/fips140/hkdf/hkdf.go:54` forwards `Key(..., keyLen)` directly into `Expand`, preserving the negative value.

The public wrappers in `src/crypto/hkdf/hkdf.go:48` and `src/crypto/hkdf/hkdf.go:65` only reject values greater than the HKDF maximum. Negative values bypass that check and are forwarded to the internal implementation.

A negative non-constant length therefore triggers:

```text
runtime error: makeslice: cap out of range
```

## Why This Is A Real Bug

The affected APIs return errors for invalid HKDF output lengths, but negative lengths panic before normal validation. If an application derives HKDF lengths from untrusted input or unchecked configuration, the panic can terminate the request handler or process when not recovered.

## Fix Requirement

Reject negative HKDF output lengths before any allocation using that length. The rejection should follow the existing API behavior by returning an error rather than allowing a runtime panic.

## Patch Rationale

The patch adds explicit negative-length validation before `make([]byte, 0, keyLen)` is reached. This preserves the existing maximum-length validation while ensuring all invalid length values are handled through controlled error paths.

## Residual Risk

None

## Patch

`048-negative-hkdf-length-panics.patch`