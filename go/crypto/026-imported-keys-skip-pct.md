# Imported Keys Skip PCT

## Classification

Vulnerability: medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/mlkem/mlkem768.go:211`

## Summary

Imported ML-KEM-768 decapsulation keys created from a 64-byte seed skip the pairwise consistency test before being recorded as FIPS-approved. The generated-key path performs the PCT, but the seed-import path only validates length, derives the key, and calls `fips140.RecordApproved()`.

## Provenance

Reported by Swival Security Scanner: https://swival.dev

## Preconditions

Caller imports a 64-byte seed via exported `NewDecapsulationKey768`.

## Proof

`NewDecapsulationKey768` reaches `newKeyFromSeed`, which only checks `len(seed) == SeedSize`, slices the seed into `d` and `z`, and calls `kemKeyGen(dk, d, z)`.

Unlike `generateKey` at `src/crypto/internal/fips140/mlkem/mlkem768.go:174`, this path does not call:

```go
fips140.PCT("ML-KEM PCT", func() error { return kemPCT(dk) })
```

before `fips140.RecordApproved()`.

The local `kemPCT` comment at `src/crypto/internal/fips140/mlkem/mlkem768.go:310` states that the ML-KEM PCT is performed when keys are generated/imported, before export or first use. `src/crypto/internal/fips140/cast.go:70` shows `fips140.PCT` is the mechanism that runs and enforces the test in FIPS mode.

## Why This Is A Real Bug

The imported-key path is reachable through exported API `NewDecapsulationKey768`. It records the imported key as approved without executing the documented PCT required for generated/imported keys. In FIPS mode, omitting the `fips140.PCT` call bypasses the consistency-test enforcement entirely.

## Fix Requirement

Call `fips140.PCT(kemPCT)` in `newKeyFromSeed` after `kemKeyGen` succeeds and before `fips140.RecordApproved()`.

## Patch Rationale

The patch aligns imported seed-derived keys with generated keys by running the same ML-KEM PCT before approval. This preserves the documented invariant that generated/imported keys are consistency-tested before export or first use.

## Residual Risk

None

## Patch

`026-imported-keys-skip-pct.patch`