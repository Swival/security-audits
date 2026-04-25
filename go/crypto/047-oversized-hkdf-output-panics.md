# Oversized HKDF Output Panics

## Classification
Validation gap. Severity: medium. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140/hkdf/hkdf.go:37`

## Summary
Internal HKDF expansion accepts an oversized `keyLen` and can panic when the HKDF block counter wraps after 255 iterations. A reachable TLS 1.3 exporter path forwards caller-controlled output length into this internal HKDF path, allowing a caller to crash the process instead of receiving an error.

## Provenance
Reported by Swival Security Scanner: https://swival.dev

## Preconditions
Caller supplies `keyLen` greater than `255 * hash.Size()` to an internal HKDF expansion path.

## Proof
`keyLen` enters `Expand` directly and controls the output loop bound. Each loop iteration increments a `uint8` counter and appends at most one HMAC output block. If the requested length still has not been satisfied after counter value 255, `counter++` wraps to 0 and triggers `panic("hkdf: counter overflow")`.

The public `crypto/hkdf` wrapper rejects oversized lengths, but TLS 1.3 exporter code bypasses that wrapper:
- `src/crypto/tls/key_schedule.go:49` calls `expMasterSecret.Exporter(..., length)` and always returns `nil` error.
- `src/crypto/internal/fips140/tls13/tls13.go:173` forwards `length` into `ExpandLabel`.
- `src/crypto/internal/fips140/tls13/tls13.go:39` reaches internal `hkdf.Expand`.

A local proof of concept completed a TLS 1.3 handshake using `TLS_AES_128_GCM_SHA256`, then called `ConnectionState.ExportKeyingMaterial("test", nil, 8161)`. SHA-256 output is 32 bytes, so the HKDF maximum is `255 * 32 == 8160`. Requesting 8161 recovered `panic: hkdf: counter overflow`.

## Why This Is A Real Bug
The failure is reachable through normal TLS 1.3 exporter API usage with caller-controlled output length. The function should reject invalid length requests and return an error, not crash the process. The panic is deterministic for lengths above the HKDF maximum.

## Fix Requirement
Reject output lengths greater than `255 * hash.Size()` before entering the HKDF expansion loop, or otherwise return an error instead of allowing the internal counter overflow panic.

## Patch Rationale
The patch adds explicit bounds validation for HKDF output length before loop execution. This preserves valid HKDF behavior, prevents counter wraparound, and converts an unchecked panic condition into controlled input rejection.

## Residual Risk
None

## Patch
`047-oversized-hkdf-output-panics.patch`