# PBKDF2 Accepts Nonpositive Iterations
## Classification
Validation gap. Severity: medium. Confidence: certain.

## Affected Locations
`src/crypto/internal/fips140/pbkdf2/pbkdf2.go:58`

## Summary
`pbkdf2.Key` accepted `iter <= 0` and still returned derived key material. Nonpositive iteration counts skipped the PBKDF2 repeat loop and produced the same effective output as a single iteration instead of rejecting invalid input.

## Provenance
Verified from the supplied finding and reproducer. Originally identified by Swival Security Scanner: https://swival.dev

## Preconditions
Caller supplies `iter <= 0` to public `crypto/pbkdf2.Key` or internal `crypto/internal/fips140/pbkdf2.Key` with a positive `keyLength`.

## Proof
The public wrapper forwards `iter` unchanged to the internal implementation. The internal implementation validated `keyLength <= 0` but did not validate `iter <= 0`.

For each output block, the implementation always computed `U_1`, copied it into the block accumulator, and appended output bytes. The loop:

```go
for n := 2; n <= iter; n++ {
```

was skipped when `iter <= 0`, so invalid iteration counts succeeded and returned one-iteration PBKDF2 output.

## Why This Is A Real Bug
PBKDF2 requires a positive iteration count. Accepting zero or negative values silently weakens password-derived keys by reducing the work factor to one PRF evaluation per block. This is reachable through the public API and can occur when applications expect invalid iteration counts to fail.

## Fix Requirement
Reject `iter <= 0` before deriving any block or producing output.

## Patch Rationale
The patch adds explicit validation for nonpositive iteration counts at the start of PBKDF2 key derivation. This prevents invalid inputs from reaching block generation and preserves the existing behavior for valid positive iteration counts.

## Residual Risk
None

## Patch
`049-pbkdf2-accepts-nonpositive-iterations.patch`