# Zero Exponent Returns Base

## Classification

Logic error, medium severity. Confidence: certain.

## Affected Locations

`src/crypto/internal/fips140/bigmod/nat.go:1022`

## Summary

`ExpShortVarTime` returns the input base when called with `e == 0`. Modular exponentiation requires `x^0 mod m == 1 mod m`, so the function returns an incorrect result for reduced bases other than one under any odd modulus.

## Provenance

Verified finding from Swival Security Scanner: https://swival.dev

## Preconditions

- Caller invokes `ExpShortVarTime` with `e == 0`.
- `x` is reduced modulo `m`.
- `m` is odd.
- `x != 1 mod m`.

## Proof

`ExpShortVarTime` converts `x` into Montgomery form and copies it into `out`. When `e == 0`, `bits.Len(e)` is `0`, causing the exponentiation loop to be skipped. The final `montgomeryReduction(out)` converts the copied Montgomery base back to normal representation, so the function returns `x mod m`.

Concrete trigger:

```text
m = 5
x = 3
e = 0
```

Expected result:

```text
3^0 mod 5 = 1
```

Actual result before patch:

```text
3
```

## Why This Is A Real Bug

The zero exponent case is mathematically defined and reachable through the public behavior of modular exponentiation. Returning the base violates modular exponentiation semantics and can corrupt callers that rely on `ExpShortVarTime` for arithmetic correctness.

## Fix Requirement

Initialize the accumulator to Montgomery one, or special-case `e == 0` to return `1 mod m`.

## Patch Rationale

The patch ensures the zero-exponent path returns the modular identity instead of the base. This preserves the expected exponentiation invariant while avoiding the skipped-loop behavior that previously left `out` initialized as `x`.

## Residual Risk

None

## Patch

`021-zero-exponent-returns-base.patch`