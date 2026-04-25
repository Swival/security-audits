# Invalid Order Loops Forever

## Classification

Validation gap, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/ecdsa/ecdsa_legacy.go:215`

## Summary

Legacy ECDSA generation/signing can loop forever when used with a custom `elliptic.Curve` whose `Params().N <= 1`. The legacy random field element helper only returns when it samples `k != 0 && k < N`; for invalid orders `<= 1`, that condition is impossible.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

Caller supplies a custom `elliptic.Curve` whose `Params().N <= 1`, and the randomness reader continues returning bytes without error.

## Proof

Custom curve parameters reach `generateLegacy` directly and reach `signLegacy` through `priv.Curve`.

`signLegacy` previously rejected only `N == 0`, allowing `N == 1` and negative orders into `randFieldElement`. `generateLegacy` also allowed invalid orders into `randFieldElement`.

`randFieldElement` reads bytes derived from `c.Params().N` and loops until:

```go
k.Sign() != 0 && k.Cmp(N) < 0
```

For `N == 1`, possible sampled values after truncation cannot satisfy `k != 0 && k < 1`. For `N <= 0`, no nonnegative sampled `k` can satisfy `k < N`.

A custom-curve PoC with `N = 1` confirmed `ecdsa.GenerateKey` remained running past a timeout instead of returning.

## Why This Is A Real Bug

The loop termination condition is mathematically unsatisfiable for invalid curve orders `<= 1`. With a non-erroring reader, the affected operation consumes CPU indefinitely and never returns.

This is reachable through public ECDSA APIs when callers provide custom curves.

## Fix Requirement

Reject curve orders `<= 1` before calling `randFieldElement`.

## Patch Rationale

The patch adds explicit validation for invalid curve order values before legacy ECDSA key generation or signing attempts to sample a random field element. This preserves the existing behavior for valid curves while converting an infinite loop into a deterministic error for invalid custom curves.

## Residual Risk

None

## Patch

Patch file: `067-invalid-order-loops-forever.patch`